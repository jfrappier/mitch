package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/store"
)

const testToken = "test-token-0123456789"

// fakeScans is an in-memory ScanSource with two scans.
type fakeScans struct {
	summaries   []store.ScanSummary
	inventories map[string]scan.Inventory
	listError   error
}

func (f *fakeScans) ListScans(ctx context.Context) ([]store.ScanSummary, error) {
	return f.summaries, f.listError
}

func (f *fakeScans) LoadScan(ctx context.Context, id string) ([]byte, error) {
	inventory, found := f.inventories[id]
	if !found {
		return nil, fmt.Errorf("scan %q: %w", id, store.ErrScanNotFound)
	}
	return json.Marshal(inventory)
}

// newFakeScans has an older scan "old1" and a newer scan "new2". The newer
// one adds a mount, and its description holds HTML that must be escaped.
func newFakeScans() *fakeScans {
	older := scan.Inventory{
		StartedAt:    time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC),
		VaultAddress: "http://127.0.0.1:8200",
		Health:       scan.Health{Version: "2.2.2"},
		Namespaces: []scan.NamespaceInventory{{
			Path:           "",
			SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}},
			ACLPolicies:    []scan.Policy{{Name: "app", Text: "path \"x\" {}\n"}},
		}},
	}
	newer := older
	newer.StartedAt = older.StartedAt.Add(time.Hour)
	newer.Namespaces = []scan.NamespaceInventory{{
		Path: "",
		SecretsEngines: []scan.Mount{
			{Path: "secret/", Type: "kv"},
			{Path: "added/", Type: "kv", Description: "<script>alert(1)</script>"},
		},
		ACLPolicies: []scan.Policy{{Name: "app", Text: "path \"x\" {}\n"}},
	}}

	return &fakeScans{
		summaries: []store.ScanSummary{
			{ID: "new2", StartedAt: newer.StartedAt, FinishedAt: newer.StartedAt},
			{ID: "old1", StartedAt: older.StartedAt, FinishedAt: older.StartedAt},
		},
		inventories: map[string]scan.Inventory{"old1": older, "new2": newer},
	}
}

func newTestServer(t *testing.T, scans ScanSource) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewServer(scans, logger, testToken)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	testServer := httptest.NewServer(server.Handler())
	t.Cleanup(testServer.Close)
	return testServer
}

// pageResult is what a test needs from a response. The body is already
// read and closed.
type pageResult struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

// get requests a page with or without the session cookie, and does not
// follow redirects, so tests see exactly what the server sent.
func get(t *testing.T, testServer *httptest.Server, path string, withCookie bool) (pageResult, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, testServer.URL+path, nil)
	if err != nil {
		t.Fatalf("building the request failed: %v", err)
	}
	if withCookie {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: testToken})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading %s failed: %v", path, err)
	}
	result := pageResult{StatusCode: response.StatusCode, Header: response.Header, Cookies: response.Cookies()}
	return result, string(body)
}

func TestPagesNeedTheToken(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	for _, path := range []string{"/", "/scans/old1", "/diff?from=old1&to=new2"} {
		response, body := get(t, testServer, path, false)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without the cookie: HTTP %d, want 401", path, response.StatusCode)
		}
		if strings.Contains(body, "secret/") {
			t.Errorf("%s without the cookie leaked scan data:\n%s", path, body)
		}
	}
}

func TestWrongCookieIsRejected(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	request, _ := http.NewRequest(http.MethodGet, testServer.URL+"/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "guess"})
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong cookie: HTTP %d, want 401", response.StatusCode)
	}
}

func TestLoginSetsCookieAndRedirects(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())

	response, _ := get(t, testServer, "/login?token=wrong", false)
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: HTTP %d, want 401", response.StatusCode)
	}

	response, _ = get(t, testServer, "/login?token="+testToken, false)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" {
		t.Fatalf("login: HTTP %d to %q, want 303 to /", response.StatusCode, response.Header.Get("Location"))
	}
	cookies := response.Cookies
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value != testToken {
		t.Fatalf("login set the wrong cookies: %+v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("the session cookie must be HttpOnly and SameSite=Strict: %+v", cookies[0])
	}
}

func TestScanListLinksReportsAndDiffs(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, body := get(t, testServer, "/", true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d:\n%s", response.StatusCode, body)
	}
	for _, expected := range []string{`href="/scans/new2"`, `href="/scans/old1"`, `href="/diff?from=old1&amp;to=new2"`, "first scan", "2026-11-13 10:00:00 UTC"} {
		if !strings.Contains(body, expected) {
			t.Errorf("scan list is missing %q:\n%s", expected, body)
		}
	}
}

func TestEmptyScanList(t *testing.T) {
	testServer := newTestServer(t, &fakeScans{})
	_, body := get(t, testServer, "/", true)
	if !strings.Contains(body, "No saved scans yet") {
		t.Errorf("empty list message missing:\n%s", body)
	}
}

func TestReportPage(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, body := get(t, testServer, "/scans/new2", true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d:\n%s", response.StatusCode, body)
	}
	for _, expected := range []string{"Scan new2", "Vault 2.2.2", "added/", "<td>(root)</td>", "Not collected"} {
		if !strings.Contains(body, expected) {
			t.Errorf("report is missing %q:\n%s", expected, body)
		}
	}
	// Text from Vault is escaped, so it can never run as HTML.
	if strings.Contains(body, "<script>") {
		t.Errorf("unescaped HTML from the scan reached the page:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the escaped description is missing:\n%s", body)
	}
}

func TestUnknownScanIs404(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, body := get(t, testServer, "/scans/nope", true)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("HTTP %d, want 404", response.StatusCode)
	}
	if !strings.Contains(body, `there is no saved scan &#34;nope&#34;`) {
		t.Errorf("error page is missing the reason:\n%s", body)
	}
}

func TestDiffPage(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, body := get(t, testServer, "/diff?from=old1&to=new2", true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d:\n%s", response.StatusCode, body)
	}
	for _, expected := range []string{"Secrets engines", `<span class="added">+ added/ (kv)</span>`} {
		if !strings.Contains(body, expected) {
			t.Errorf("diff is missing %q:\n%s", expected, body)
		}
	}

	_, body = get(t, testServer, "/diff?from=old1&to=old1", true)
	if !strings.Contains(body, "No changes.") {
		t.Errorf("same-scan diff should say No changes:\n%s", body)
	}
}

func TestDiffNeedsBothScans(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, _ := get(t, testServer, "/diff?from=old1", true)
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("HTTP %d, want 400", response.StatusCode)
	}
	response, _ = get(t, testServer, "/diff?from=old1&to=nope", true)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("HTTP %d, want 404", response.StatusCode)
	}
}

func TestListErrorIs500(t *testing.T) {
	testServer := newTestServer(t, &fakeScans{listError: fmt.Errorf("disk on fire")})
	response, body := get(t, testServer, "/", true)
	if response.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "disk on fire") {
		t.Errorf("HTTP %d, want 500 with the reason:\n%s", response.StatusCode, body)
	}
}

func TestOnlyGETIsAllowed(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	request, _ := http.NewRequest(http.MethodPost, testServer.URL+"/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: testToken})
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: HTTP %d, want 405", response.StatusCode)
	}
}

func TestSecurityHeadersAndStylesheet(t *testing.T) {
	testServer := newTestServer(t, newFakeScans())
	response, body := get(t, testServer, "/static/style.css", false)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "prefers-color-scheme") {
		t.Fatalf("stylesheet: HTTP %d", response.StatusCode)
	}
	expectedHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	}
	for name, expected := range expectedHeaders {
		if got := response.Header.Get(name); got != expected {
			t.Errorf("header %s = %q, want %q", name, got, expected)
		}
	}
}

func TestNewServerNeedsAToken(t *testing.T) {
	_, err := NewServer(newFakeScans(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if err == nil {
		t.Error("NewServer must refuse an empty token")
	}
}

func TestNewAccessTokenIsRandom(t *testing.T) {
	first, err := NewAccessToken()
	if err != nil {
		t.Fatalf("NewAccessToken failed: %v", err)
	}
	second, _ := NewAccessToken()
	if len(first) != 64 || first == second {
		t.Errorf("tokens must be 64 hex characters and differ: %q %q", first, second)
	}
}

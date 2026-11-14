package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/exitcode"
)

// lockedBuffer is a bytes.Buffer that the serve goroutine can write while
// the test reads it.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

// loginLinkPattern finds the link "mitch serve" prints.
var loginLinkPattern = regexp.MustCompile(`http://127\.0\.0\.1:\d+/login\?token=[0-9a-f]{64}`)

func TestServeShowsSavedScansAndStops(t *testing.T) {
	path := testDatabase(t)
	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\n%s", exitCode, stderr)
	}
	scanID := saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), `{"vault_address":"http://127.0.0.1:8200","namespaces":[]}`)

	// Replace Ctrl+C with a context the test cancels.
	stopContext, stop := context.WithCancel(context.Background())
	original := stopSignalContext
	stopSignalContext = func() (context.Context, context.CancelFunc) { return stopContext, stop }
	t.Cleanup(func() { stopSignalContext = original })

	stdout := &lockedBuffer{}
	serveStderr := &lockedBuffer{}
	finished := make(chan int, 1)
	go func() {
		finished <- Run([]string{"serve", "--listen", "127.0.0.1:0"}, stdout, serveStderr)
	}()

	// Wait for the link, up to 10 seconds.
	link := ""
	for attempt := 0; attempt < 100 && link == ""; attempt++ {
		link = loginLinkPattern.FindString(stdout.String())
		if link == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if link == "" {
		stop()
		t.Fatalf("serve printed no login link.\nstdout: %s\nstderr: %s", stdout.String(), serveStderr.String())
	}

	// Opening the link logs in and lands on the scan list.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New failed: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	response, err := client.Get(link)
	if err != nil {
		t.Fatalf("opening the login link failed: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), scanID) {
		t.Errorf("scan list: HTTP %d, want 200 listing %s:\n%s", response.StatusCode, scanID, body)
	}

	// The token never reaches the log.
	token := link[strings.Index(link, "token=")+len("token="):]
	if strings.Contains(serveStderr.String(), token) {
		t.Errorf("the access token was logged:\n%s", serveStderr.String())
	}

	stop()
	select {
	case exitCode = <-finished:
		if exitCode != exitcode.Success {
			t.Errorf("serve exited %d after stop, want 0\nstderr: %s", exitCode, serveStderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop within 10 seconds")
	}
}

func TestServeRejectsBadListenAddress(t *testing.T) {
	testDatabase(t)
	exitCode, _, stderr := runForTest("serve", "--listen", "8484")
	if exitCode != exitcode.UsageError {
		t.Errorf("exit %d, want %d", exitCode, exitcode.UsageError)
	}
	if !strings.Contains(stderr, "is not ADDRESS:PORT") {
		t.Errorf("stderr is missing the reason: %s", stderr)
	}
}

func TestServeFailsWithoutDatabase(t *testing.T) {
	testDatabase(t) // points MITCH_DB at a file that does not exist yet
	exitCode, _, stderr := runForTest("serve", "--listen", "127.0.0.1:0")
	if exitCode != exitcode.GeneralError {
		t.Errorf("exit %d, want %d\n%s", exitCode, exitcode.GeneralError, stderr)
	}
	if !strings.Contains(stderr, "cannot open the database") {
		t.Errorf("stderr is missing the reason: %s", stderr)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true,
		"127.1.2.3": true,
		"::1":       true,
		"localhost": true,
		"0.0.0.0":   false,
		"":          false,
		"10.0.0.5":  false,
		"example":   false,
	}
	for host, expected := range cases {
		if got := isLoopbackHost(host); got != expected {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, expected)
		}
	}
}

func TestLoginLink(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8484": "http://127.0.0.1:8484/login?token=abc",
		"0.0.0.0:8484":   "http://127.0.0.1:8484/login?token=abc",
		"[::]:9000":      "http://127.0.0.1:9000/login?token=abc",
		"[::1]:9000":     "http://[::1]:9000/login?token=abc",
	}
	for address, expected := range cases {
		tcpAddress, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			t.Fatalf("ResolveTCPAddr(%q) failed: %v", address, err)
		}
		if got := loginLink(tcpAddress, "abc"); got != expected {
			t.Errorf("loginLink(%s) = %q, want %q", address, got, expected)
		}
	}
}

// Package web is the read-only web UI that "mitch serve" runs.
//
// It shows the saved scans, a report for each scan, and the changes between
// two scans. It never contacts Vault and never changes the database: every
// page is built from the same saved, encrypted scans the CLI reads.
//
// Every page needs an access token. "mitch serve" prints a link with the
// token once; opening it stores the token in a cookie for that browser. This
// keeps other users and other web pages on the same machine out, because
// they can reach 127.0.0.1 but do not know the token.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/store"
)

// The page templates and the stylesheet are compiled into the binary, so the
// UI needs no files and no JavaScript at runtime.
//
//go:embed templates/*.html static/*.css
var embeddedFiles embed.FS

// sessionCookieName is the cookie that holds the access token.
const sessionCookieName = "mitch_session"

// tokenBytes is the access token length in random bytes (256 bits).
const tokenBytes = 32

// ScanSource is where the UI reads saved scans. *store.Store is one.
type ScanSource interface {
	// ListScans returns every saved scan, newest first, without decrypting.
	ListScans(ctx context.Context) ([]store.ScanSummary, error)
	// LoadScan decrypts one saved scan and returns its inventory JSON.
	LoadScan(ctx context.Context, id string) ([]byte, error)
}

// Server holds what every page needs.
type Server struct {
	scans       ScanSource
	logger      *slog.Logger
	accessToken string
	pages       map[string]*template.Template
}

// NewServer prepares the UI. accessToken is the secret every request must
// carry; use NewAccessToken to make one.
func NewServer(scans ScanSource, logger *slog.Logger, accessToken string) (*Server, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("the web UI needs an access token")
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	server := &Server{
		scans:       scans,
		logger:      logging.ForComponent(logger, "web"),
		accessToken: accessToken,
		pages:       pages,
	}
	return server, nil
}

// NewAccessToken returns a random token as hex text.
func NewAccessToken() (string, error) {
	randomBytes := make([]byte, tokenBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("making a random access token failed: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}

// Handler returns the HTTP handler for the whole UI.
func (s *Server) Handler() http.Handler {
	routes := http.NewServeMux()
	routes.HandleFunc("GET /login", s.handleLogin)
	routes.HandleFunc("GET /{$}", s.requireToken(s.handleScanList))
	routes.HandleFunc("GET /scans/{id}", s.requireToken(s.handleReport))
	routes.HandleFunc("GET /diff", s.requireToken(s.handleDiff))

	staticFiles, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		// The folder is embedded at build time, so this cannot happen in a
		// binary that compiled.
		panic(fmt.Sprintf("the embedded static folder is missing: %v", err))
	}
	routes.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFiles)))

	return securityHeaders(routes)
}

// handleLogin checks the token from the link "mitch serve" printed, stores
// it in a cookie, and sends the browser to the scan list. The redirect
// removes the token from the address bar.
func (s *Server) handleLogin(response http.ResponseWriter, request *http.Request) {
	token := request.URL.Query().Get("token")
	if !s.tokenMatches(token) {
		s.logger.Warn("someone opened the login link with a wrong or missing token",
			logging.FieldOperation, "login",
			"remote_address", request.RemoteAddr,
		)
		s.renderError(response, http.StatusUnauthorized, "That access link is not valid. Use the link \"mitch serve\" printed in the terminal.")
		return
	}

	// Secure is not set: the UI is plain HTTP on 127.0.0.1, and browsers
	// such as Safari drop Secure cookies sent over http://, which would make
	// logging in impossible. HttpOnly and SameSite=Strict still apply.
	http.SetCookie(response, &http.Cookie{ //nolint:gosec // G124: Secure would break plain-HTTP 127.0.0.1, see above
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,                    // page scripts cannot read it
		SameSite: http.SameSiteStrictMode, // other sites cannot send it
	})
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

// requireToken wraps a page so it only runs for a browser that has the
// access token cookie.
func (s *Server) requireToken(page http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil || !s.tokenMatches(cookie.Value) {
			s.renderError(response, http.StatusUnauthorized, "Open the link \"mitch serve\" printed in the terminal to use this page.")
			return
		}
		page(response, request)
	}
}

// tokenMatches compares in constant time, so response timing does not
// reveal how much of a guess was right.
func (s *Server) tokenMatches(candidate string) bool {
	if candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.accessToken)) == 1
}

// securityHeaders adds headers to every response:
//   - Content-Security-Policy allows only this server's stylesheet: no
//     scripts, no other sites, no framing.
//   - Cache-Control no-store keeps decrypted pages out of the browser cache.
//   - Referrer-Policy no-referrer keeps page addresses from leaking.
//   - X-Content-Type-Options nosniff stops the browser guessing file types.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		headers := response.Header()
		headers.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		headers.Set("Cache-Control", "no-store")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}

// NewHTTPServer wraps the handler in an http.Server with timeouts, so a slow
// or stuck client cannot hold connections open forever.
func NewHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

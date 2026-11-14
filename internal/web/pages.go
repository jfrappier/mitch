package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/jfrappier/mitch/internal/diff"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/report"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/store"
)

// Page names. Each is a file in templates/ that defines "content", shown
// inside templates/layout.html.
const (
	pageScans  = "scans"
	pageReport = "report"
	pageDiff   = "diff"
	pageError  = "error"
)

// timeLayout is how times are shown (always UTC), the same as the CLI.
const timeLayout = "2006-01-02 15:04:05 UTC"

// templateFunctions are helpers the templates can call.
var templateFunctions = template.FuncMap{
	// when formats a time in UTC.
	"when": func(value time.Time) string {
		return value.UTC().Format(timeLayout)
	},
	// namespace shows the root namespace as "(root)", the label the report
	// uses, instead of an empty cell. Report rows already carry the label;
	// scan gap rows do not.
	"namespace": func(path string) string {
		if path == "" {
			return "(root)"
		}
		return path
	},
	// sectionTitle is the heading for a diff section.
	"sectionTitle": diff.SectionTitle,
}

// parsePages reads every page template together with the shared layout.
func parsePages() (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	for _, name := range []string{pageScans, pageReport, pageDiff, pageError} {
		parsed, err := template.New("layout.html").Funcs(templateFunctions).ParseFS(embeddedFiles, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("reading the %s page template failed: %w", name, err)
		}
		pages[name] = parsed
	}
	return pages, nil
}

// scanListRow is one line of the scan list. PreviousID is the scan saved
// just before it, for the "changes since previous" link; empty for the oldest.
type scanListRow struct {
	Scan       store.ScanSummary
	PreviousID string
}

// handleScanList shows every saved scan, newest first.
func (s *Server) handleScanList(response http.ResponseWriter, request *http.Request) {
	summaries, err := s.scans.ListScans(request.Context())
	if err != nil {
		s.logger.Error("listing saved scans failed", logging.FieldOperation, "list_scans", logging.FieldError, err.Error())
		s.renderError(response, http.StatusInternalServerError, "Listing saved scans failed: "+err.Error())
		return
	}

	rows := []scanListRow{}
	for index, summary := range summaries {
		row := scanListRow{Scan: summary}
		// The list is newest first, so the previous scan is the next entry.
		if index+1 < len(summaries) {
			row.PreviousID = summaries[index+1].ID
		}
		rows = append(rows, row)
	}
	s.render(response, pageScans, map[string]any{"Title": "Saved scans", "Rows": rows})
}

// handleReport shows the report for one scan, the same one "mitch report" prints.
func (s *Server) handleReport(response http.ResponseWriter, request *http.Request) {
	scanID := request.PathValue("id")
	inventory, status, err := s.loadInventory(request, scanID)
	if err != nil {
		s.renderError(response, status, err.Error())
		return
	}
	built := report.Build(scanID, inventory)
	s.render(response, pageReport, map[string]any{"Title": "Scan " + scanID, "Report": built})
}

// handleDiff shows the changes between two scans, the same as "mitch diff".
// Both ?from= and ?to= are required.
func (s *Server) handleDiff(response http.ResponseWriter, request *http.Request) {
	fromID := request.URL.Query().Get("from")
	toID := request.URL.Query().Get("to")
	if fromID == "" || toID == "" {
		s.renderError(response, http.StatusBadRequest, "A comparison needs two scans: ?from=ID&to=ID.")
		return
	}

	fromInventory, status, err := s.loadInventory(request, fromID)
	if err != nil {
		s.renderError(response, status, err.Error())
		return
	}
	toInventory, status, err := s.loadInventory(request, toID)
	if err != nil {
		s.renderError(response, status, err.Error())
		return
	}

	compared, err := diff.Compare(fromID, fromInventory, toID, toInventory)
	if err != nil {
		s.logger.Error("comparing scans failed", logging.FieldOperation, "diff", "from", fromID, "to", toID, logging.FieldError, err.Error())
		s.renderError(response, http.StatusInternalServerError, "Comparing the scans failed: "+err.Error())
		return
	}
	s.render(response, pageDiff, map[string]any{"Title": "Changes from " + fromID + " to " + toID, "Diff": compared})
}

// loadInventory decrypts one saved scan. On failure it returns the HTTP
// status to show: 404 for an unknown scan, 500 for anything else.
func (s *Server) loadInventory(request *http.Request, scanID string) (scan.Inventory, int, error) {
	inventoryJSON, err := s.scans.LoadScan(request.Context(), scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return scan.Inventory{}, http.StatusNotFound, fmt.Errorf("there is no saved scan %q", scanID)
		}
		s.logger.Error("loading a saved scan failed", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		return scan.Inventory{}, http.StatusInternalServerError, fmt.Errorf("loading scan %s failed: %w", scanID, err)
	}

	var inventory scan.Inventory
	err = json.Unmarshal(inventoryJSON, &inventory)
	if err != nil {
		s.logger.Error("a saved scan is not a valid inventory", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		return scan.Inventory{}, http.StatusInternalServerError, fmt.Errorf("scan %s is not a valid inventory: %w", scanID, err)
	}
	return inventory, http.StatusOK, nil
}

// render fills a page template into a buffer first, so a template error
// becomes a clean error page instead of half a page.
func (s *Server) render(response http.ResponseWriter, page string, data map[string]any) {
	s.renderWithStatus(response, http.StatusOK, page, data)
}

// renderError shows the error page with a message and an HTTP status.
func (s *Server) renderError(response http.ResponseWriter, status int, message string) {
	s.renderWithStatus(response, status, pageError, map[string]any{"Title": http.StatusText(status), "Message": message, "Status": status})
}

// renderWithStatus does the work for render and renderError.
func (s *Server) renderWithStatus(response http.ResponseWriter, status int, page string, data map[string]any) {
	var buffer bytes.Buffer
	err := s.pages[page].Execute(&buffer, data)
	if err != nil {
		s.logger.Error("building a page failed", logging.FieldOperation, "render", "page", page, logging.FieldError, err.Error())
		http.Error(response, "building the page failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(status)
	_, err = buffer.WriteTo(response)
	if err != nil {
		s.logger.Warn("sending a page failed", logging.FieldOperation, "render", "page", page, logging.FieldError, err.Error())
	}
}

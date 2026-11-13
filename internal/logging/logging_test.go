package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestTextFormatHasRequiredFields checks that a text log line contains the
// standard fields in key=value form.
func TestTextFormatHasRequiredFields(t *testing.T) {
	var output bytes.Buffer

	logger, err := New(Options{Output: &output, Format: FormatText, Level: LevelInfo})
	if err != nil {
		t.Fatalf("New returned an unexpected error: %v", err)
	}

	componentLogger := ForComponent(logger, "test")
	componentLogger.Info("hello", FieldOperation, "say_hello")

	line := output.String()
	expectedParts := []string{"time=", "level=INFO", "msg=hello", "component=test", "operation=say_hello"}
	for _, expected := range expectedParts {
		if !strings.Contains(line, expected) {
			t.Errorf("log line is missing %q\nfull line: %s", expected, line)
		}
	}
}

// TestJSONFormatHasRequiredFields checks that a JSON log line parses as JSON
// and contains the standard fields.
func TestJSONFormatHasRequiredFields(t *testing.T) {
	var output bytes.Buffer

	logger, err := New(Options{Output: &output, Format: FormatJSON, Level: LevelInfo})
	if err != nil {
		t.Fatalf("New returned an unexpected error: %v", err)
	}

	componentLogger := ForComponent(logger, "test")
	componentLogger.Info("hello", FieldOperation, "say_hello")

	var parsed map[string]any
	err = json.Unmarshal(output.Bytes(), &parsed)
	if err != nil {
		t.Fatalf("log line is not valid JSON: %v\nfull line: %s", err, output.String())
	}

	expectedKeys := []string{"time", "level", "msg", FieldComponent, FieldOperation}
	for _, key := range expectedKeys {
		_, found := parsed[key]
		if !found {
			t.Errorf("JSON log line is missing key %q\nfull line: %s", key, output.String())
		}
	}
}

// TestLevelFiltersLowerLevels checks that lines below the chosen level are not written.
func TestLevelFiltersLowerLevels(t *testing.T) {
	var output bytes.Buffer

	logger, err := New(Options{Output: &output, Format: FormatText, Level: LevelWarn})
	if err != nil {
		t.Fatalf("New returned an unexpected error: %v", err)
	}

	logger.Info("this should not appear")

	if output.Len() != 0 {
		t.Errorf("expected no output at warn level, got: %s", output.String())
	}
}

// TestRejectsUnknownValues checks that bad flag values fail loudly instead of
// silently falling back to a default.
func TestRejectsUnknownValues(t *testing.T) {
	testCases := []struct {
		name    string
		options Options
	}{
		{name: "unknown format", options: Options{Output: &bytes.Buffer{}, Format: "xml", Level: LevelInfo}},
		{name: "unknown level", options: Options{Output: &bytes.Buffer{}, Format: FormatText, Level: "loud"}},
		{name: "missing output", options: Options{Output: nil, Format: FormatText, Level: LevelInfo}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(testCase.options)
			if err == nil {
				t.Errorf("expected an error for %s, got none", testCase.name)
			}
		})
	}
}

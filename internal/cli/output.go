package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrappier/mitch/internal/logging"
)

// Output formats for commands that show saved scans to people ("report" and "diff").
const (
	formatMarkdown = "markdown"
	formatJSON     = "json"
)

// File extensions that pick the format of an --output file.
const (
	extensionMarkdown = ".md"
	extensionJSON     = ".json"
)

// renderedOutput holds one result in both formats, so the terminal and an
// --output file can each get the format they need.
type renderedOutput struct {
	markdown []byte
	json     []byte
}

// checkOutputFlags checks --format and the --output file extension before
// anything else runs, so a typo fails before the passphrase is asked for.
func checkOutputFlags(format string, outputPath string) error {
	if format != formatMarkdown && format != formatJSON {
		return fmt.Errorf("--format must be %q or %q, not %q", formatMarkdown, formatJSON, format)
	}
	if outputPath != "" {
		_, err := fileFormatFor(outputPath)
		if err != nil {
			return err
		}
	}
	return nil
}

// fileFormatFor picks the format of an --output file from its extension.
func fileFormatFor(outputPath string) (string, error) {
	extension := strings.ToLower(filepath.Ext(outputPath))
	switch extension {
	case extensionMarkdown:
		return formatMarkdown, nil
	case extensionJSON:
		return formatJSON, nil
	default:
		return "", fmt.Errorf("--output %s must end in %s (Markdown) or %s (JSON)", outputPath, extensionMarkdown, extensionJSON)
	}
}

// writeRendered shows the result in the terminal and, with --output, also
// saves it to a file.
//
// The terminal gets Markdown, or JSON with --format json (for piping into
// tools such as jq). The file's format comes from its extension, so
// "--output report.json" saves JSON while the terminal still shows Markdown.
//
// Both hold decrypted scan data, so each logs a plain-text warning.
func writeRendered(runContext runContext, component string, format string, outputPath string, rendered renderedOutput) error {
	outputLogger := logging.ForComponent(runContext.logger, component)

	terminalContent := rendered.markdown
	if format == formatJSON {
		terminalContent = rendered.json
	}
	outputLogger.Warn("printing decrypted scan details as plain text; treat the output as sensitive",
		logging.FieldOperation, "write_output",
		"format", format,
	)
	_, err := runContext.stdout.Write(terminalContent)
	if err != nil {
		return fmt.Errorf("writing to standard output failed: %w", err)
	}

	if outputPath == "" {
		return nil
	}

	fileFormat, err := fileFormatFor(outputPath)
	if err != nil {
		return err
	}
	fileContent := rendered.markdown
	if fileFormat == formatJSON {
		fileContent = rendered.json
	}
	err = writePrivateFile(outputPath, fileContent)
	if err != nil {
		return err
	}
	outputLogger.Warn("decrypted scan details written as plain text; treat this file as sensitive",
		logging.FieldOperation, "write_output",
		"output", outputPath,
		"format", fileFormat,
	)
	return nil
}

// writePrivateFile writes content to a file readable and writable only by
// its owner, replacing anything already there.
func writePrivateFile(outputPath string, content []byte) error {
	// The user chooses the output path on purpose, so gosec's file-path
	// warning (G304) does not apply here.
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, outputFileMode) //nolint:gosec // path is the user's --output flag
	if err != nil {
		return err
	}

	// OpenFile only applies the mode to new files, so tighten an existing one too.
	err = file.Chmod(outputFileMode)
	if err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("setting permissions on %s failed: %w", outputPath, err), closeErr)
	}

	_, err = file.Write(content)
	if err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("writing %s failed: %w", outputPath, err), closeErr)
	}

	return file.Close()
}

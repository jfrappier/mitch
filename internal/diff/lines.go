package diff

import (
	"bytes"
	"io"
	"strings"
)

// maxLineComparisonCells caps the work done comparing two texts line by line.
// The comparison builds a table of (old lines x new lines) cells. ACL policies
// are small, but a very large one would use too much memory, so past this
// size the whole old text is shown as removed and the whole new text as added.
const maxLineComparisonCells = 4_000_000

// compareLines compares two texts line by line and returns only the lines
// that differ, in order. Lines only in the old text start with "- ", and
// lines only in the new text start with "+ ".
//
// It finds the longest run of lines the two texts share (the "longest common
// subsequence"), and everything outside that run is a change.
func compareLines(oldText string, newText string) []string {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)

	if len(oldLines)*len(newLines) > maxLineComparisonCells {
		return wholeTextReplaced(oldLines, newLines)
	}

	// common[i][j] is how many lines oldLines[i:] and newLines[j:] share, in order.
	common := make([][]int, len(oldLines)+1)
	for i := range common {
		common[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				common[i][j] = common[i+1][j+1] + 1
			} else {
				common[i][j] = max(common[i+1][j], common[i][j+1])
			}
		}
	}

	// Walk the table from the start and write out every line not shared.
	changed := []string{}
	i := 0
	j := 0
	for i < len(oldLines) && j < len(newLines) {
		switch {
		case oldLines[i] == newLines[j]:
			i++
			j++
		case common[i+1][j] >= common[i][j+1]:
			changed = append(changed, "- "+oldLines[i])
			i++
		default:
			changed = append(changed, "+ "+newLines[j])
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		changed = append(changed, "- "+oldLines[i])
	}
	for ; j < len(newLines); j++ {
		changed = append(changed, "+ "+newLines[j])
	}
	return changed
}

// wholeTextReplaced shows every old line as removed and every new line as added.
func wholeTextReplaced(oldLines []string, newLines []string) []string {
	changed := []string{}
	for _, line := range oldLines {
		changed = append(changed, "- "+line)
	}
	for _, line := range newLines {
		changed = append(changed, "+ "+line)
	}
	return changed
}

// splitLines splits text into lines. A trailing line break does not make an
// extra empty line, and Windows line endings are treated like Unix ones.
func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return []string{}
	}
	return strings.Split(text, "\n")
}

// bytesReader wraps a byte slice so a json.Decoder can read it.
func bytesReader(content []byte) io.Reader {
	return bytes.NewReader(content)
}

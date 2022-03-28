// Find comments inside source files of Netspoc policy language.
//
package scanner

import (
	"strings"
)

// Read one or more lines of comment and whitespace.
// Ignore trailing comment or trailing whitespace of previous statement.
func (s *Scanner) PreCmt(pos int, ign string) string {
	line1 := 0
	end := pos
	pos--
READ:
	for pos >= 0 {
		c := rune(s.src[pos])
		switch c {
		case '\n':
			line1 = pos
			fallthrough
		case ' ', '\t', '\r':
			// Whitespace
			pos--
		default:
			// Check to be ignored character.
			if strings.ContainsRune(ign, c) {
				pos--
				continue READ
			}
			// Check backwards for comment.
			i := pos
			for i >= 0 {
				switch s.src[i] {
				case '#':
					pos = i - 1
					continue READ
				case '\n':
					break READ
				}
				i--
			}
			break READ
		}
	}
	pos++

	// Ignore trailing comment or trailing whitespace of previous line.
	if pos > 0 && line1 != 0 {
		switch s.src[pos-1] {
		// Comment after list definition belongs to first element of list.
		case '\n', '=':
		default:
			pos = line1 + 1
		}
	}
	return normalizeComments(string(s.src[pos:end]), ign)
}

func normalizeComments(cmt string, ign string) string {
	var result string
	empty := true

	lines := strings.Split(cmt, "\n")
	// Ignore last entry having no trailing "\n".
	for _, line := range lines[:len(lines)-1] {
		if idx := strings.Index(line, "#"); idx != -1 {
			// Line contains comment.
			line = line[idx:] // Ignore leading whitespace
			result += line + "\n"
			empty = false
		} else if !strings.ContainsAny(line, ign) && !empty {
			// Found empty line, separating blocks of comment lines.
			// Line with ignored characters isn't empty.
			empty = true
			result += "\n"
		}
	}
	if l := len(result); l > 0 {
		result = result[:l-1]
	}
	return result
}

// Read trailing comment in source beginning at position 'pos'.
// Ignore characters in 'ign' when searching for comment.
// Returns: Found trailing comment with one preceeding whitespace or
//          empty string.
func (s *Scanner) PostCmt(pos int, ign string) string {
READ:
	for pos < len(s.src) {
		c := rune(s.src[pos])
		switch c {
		case ' ', '\t', '\r':
			// Whitespace
			pos++
		case '#':
			// Comment
			start := pos
			pos++
			for pos < len(s.src) {
				if rune(s.src[pos]) == '\n' {
					break
				}
				pos++
			}
			return " " + string(s.src[start:pos])
		default:
			// Check to be ignored character.
			if !strings.ContainsRune(ign, c) {
				break READ
			}
			pos++
		}
	}
	return ""
}

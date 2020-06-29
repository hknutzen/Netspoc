// Find comments inside source files of Netspoc policy language.
//
package printer

import (
	"github.com/hknutzen/spoc-parser/ast"
	"strings"
)

func (p *printer) ReadTrailingComment(pos int, ign string) string {
READ:
	for pos < len(p.src) {
		c := rune(p.src[pos])
		switch c {
		case ' ', '\t', '\r':
			// Whitespace
			pos++
		case '#':
			// Comment
			start := pos
			pos++
			for pos < len(p.src) {
				if rune(p.src[pos]) == '\n' {
					break
				}
				pos++
			}
			return string(p.src[start:pos])
		default:
			// Check to be ignored character.
			if strings.IndexRune(ign, c) == -1 {
				break READ
			}
			pos++
		}
	}
	return ""
}

// Find trailing comment in source beginning at position 'pos'.
// Ignore characters in 'ign' when searching for comment.
// Returns
// Found trailing comment with one preceeding whitespace or
// empty string.
//
func (p *printer) TrailingCommentAt(pos int, ign string) string {
	trailing := p.ReadTrailingComment(pos, ign)
	if trailing != "" {
		trailing = " " + trailing
	}
	return trailing
}

func (p *printer) TrailingComment(n ast.Node, ign string) string {
	return p.TrailingCommentAt(n.End(), ign)
}

func normalizeComments(com string, ign string) []string {
	var result []string
	empty := true

	lines := strings.Split(com, "\n")

	// 'lines' is known to have at least one element.
	// Comment line is known to end with "\n", even at EOF.
	// (Has been added if missing.)
	// So, any comment would result in at least two lines.

	// Ignore last entry having no trailing "\n".
	for _, line := range lines[:len(lines)-1] {
		if idx := strings.Index(line, "#"); idx != -1 {
			// Line contains comment.
			line = line[idx:] // Ignore leading whitespace
			result = append(result, line)
			empty = false
		} else if strings.IndexAny(line, ign) == -1 && !empty {
			// Found empty line, separating blocks of comment lines.
			// Line with ignored characters isn't empty.
			result = append(result, "")
			empty = true
		}
	}
	return result
}

// Read one or more lines of comment and whitespace.
// Ignore trailing comment or trailing whitespace of previous statement.
func (p *printer) ReadCommentOrWhitespaceBefore(pos int, ign string) []string {
	line1 := 0
	end := pos
	pos--
READ:
	for pos >= 0 {
		c := rune(p.src[pos])
		switch c {
		case '\n':
			line1 = pos
			fallthrough
		case ' ', '\t', '\r':
			// Whitespace
			pos--
		default:
			// Check to be ignored character.
			if strings.IndexRune(ign, c) != -1 {
				pos--
				continue READ
			}
			// Check backwards for comment.
			i := pos
			for i >= 0 {
				switch p.src[i] {
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
		switch p.src[pos-1] {
		case '\n', '=':
		default:
			pos = line1 + 1
		}
	}
	return normalizeComments(string(p.src[pos:end]), ign)
}

func (p *printer) comment(lines []string) {
	for _, line := range lines {
		p.print(line)
	}
}

func (p *printer) PreComment(n ast.Node, ign string) {
	lines := p.ReadCommentOrWhitespaceBefore(n.Pos(), ign)
	p.comment(lines)
}

func (p *printer) hasPreComment(n ast.Node, ign string) bool {
	return p.ReadCommentOrWhitespaceBefore(n.Pos(), ign) != nil
}

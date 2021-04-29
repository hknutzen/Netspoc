// Find comments inside source files of Netspoc policy language.
//
package printer

import (
	"bytes"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"strings"
)

func (p *printer) readTrailingComment(pos int, ign string) string {
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
func (p *printer) trailingCommentAt(pos int, ign string) string {
	trailing := p.readTrailingComment(pos, ign)
	if trailing != "" {
		trailing = " " + trailing
	}
	return trailing
}

func (p *printer) hasSource(n ast.Node) bool {
	if p.src == nil {
		return false
	}
	if n.Pos() < 0 {
		return false
	}
	if _, ok := n.(ast.Toplevel); ok {
		return n.Pos() != n.End()
	} else {
		return n.Pos() != 0
	}
}

func (p *printer) trailingComment(n ast.Node, ign string) string {
	if !p.hasSource(n) {
		return ""
	}
	return p.trailingCommentAt(n.End(), ign)
}

func (p *printer) getTrailing(n ast.Toplevel) string {
	if !p.hasSource(n) {
		return ""
	}
	pos := n.Pos() + len(n.GetName())
	trailing := p.trailingCommentAt(pos, "={")
	// Show trailing comment found after closing "}" if whole
	// definition is at one line.
	end := n.End()
	if trailing == "" && bytes.IndexByte(p.src[pos:end], '\n') == -1 {
		trailing = p.trailingCommentAt(end, "")
	}
	return trailing
}

func normalizeComments(com string, ign string) []string {
	var result []string
	empty := true

	lines := strings.Split(com, "\n")
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
func (p *printer) readCommentOrWhitespaceBefore(pos int, ign string) []string {
	if p.src == nil || pos < 0 {
		return nil
	}
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

func (p *printer) preComment(n ast.Node, ign string) {
	lines := p.readCommentOrWhitespaceBefore(n.Pos(), ign)
	p.comment(lines)
}

func (p *printer) hasPreComment(n ast.Node, ign string) bool {
	return p.readCommentOrWhitespaceBefore(n.Pos(), ign) != nil
}

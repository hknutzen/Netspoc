// Find comments inside source files of Netspoc policy language.
//
package printer

import (
	"github.com/hknutzen/spoc-parser/ast"
	"strings"
)

func (p *printer) comment(blocks [][]string) {
	for i, block := range blocks {
		if i != 0 {
			p.print("")
		}
		for _, line := range block {
			p.print(line)
		}
	}
}

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

// Read one or more lines of comment and whitespace.
func (p *printer) ReadCommentOrWhitespaceBefore(
	pos int, ignore string) string {

	end := pos
	pos--
READ:
	for pos >= 0 {
		c := rune(p.src[pos])
		switch c {
		case ' ', '\t', '\n', '\r':
			// Whitespace
			pos--
		default:
			// Check to be ignored character.
			if strings.IndexRune(ignore, c) != -1 {
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
	result := string(p.src[pos:end])

	// First line of file must not be recognized as trailing comment.
	if pos == 0 {
		result = "\n" + result
	}
	return result
}

func splitComments(com string, ign string) (string, [][]string) {
	var first string
	var result [][]string
	var block []string
	trailing := true

	lines := strings.Split(com, "\n")

	// 'lines' is known to have at least one element.
	// Comment line is known to end with "\n", even at EOF.
	// (Has been added if missing.)
	// So, any comment would result in at least two lines.

	// Ignore last line without trailing "\n".
	lines = lines[:len(lines)-1]
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx != -1 {
			// Line contains comment.
			line = line[idx:] // Ignore leading whitespace
			if trailing {
				first = line
			} else {
				block = append(block, line)
			}
		} else if strings.IndexAny(line, ign) == -1 &&
			!trailing && block != nil {
			// Found empty line, separating blocks of comment lines.
			// Line with ignored characters isn't empty.
			result = append(result, block)
			block = nil
		}
		trailing = false
	}

	return first, append(result, block)
}

func (p *printer) PreComment(n ast.Node, ign string) {
	com := p.ReadCommentOrWhitespaceBefore(n.Pos(), ign)
	// Ignore trailing comment in first line.
	_, result := splitComments(com, ign)
	p.comment(result)
}

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

func (p *printer) ReadCommentOrWhitespaceAfter(pos int, ign string) string {

	start := pos
READ:
	for pos < len(p.src) {
		c := rune(p.src[pos])
		switch c {
		case ' ', '\t', '\n', '\r':
			// Whitespace
			pos++
		case '#':
			// Comment
			pos++
			for {
				if rune(p.src[pos]) == '\n' {
					break
				}
				pos++
			}
		default:
			// Check to be ignored character.
			if strings.IndexRune(ign, c) == -1 {
				break READ
			}
			pos++
		}
	}
	return string(p.src[start:pos])
}

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
			for {
				switch p.src[i] {
				case '#':
					pos = i - 1
					continue READ
				case '\n':
					break READ
				default:
					i--
					if i < 0 {
						break READ
					}
				}
			}
		}
	}
	return string(p.src[pos+1 : end])
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

// Find comment lines in source beginning at position 'pos'
// up to first empty line.
// Ignore characters in 'ign'.
// These are ignored and won't terminate sequences of comments.
// Returns
// 1. Comment in same line after 'pos'.
// 2. Blocks of one or more comment lines separated by new line.
//
func (p *printer) FindCommentAfter(pos int, ign string) (string, [][]string) {
	com := p.ReadCommentOrWhitespaceAfter(pos, ign)
	return splitComments(com, ign)
}

func (p *printer) PostComment(n ast.Node, ign string) (string, [][]string) {
	return p.FindCommentAfter(n.End(), ign)
}

func (p *printer) FindCommentBefore(pos int, ign string) [][]string {
	com := p.ReadCommentOrWhitespaceBefore(pos, ign)
	_, result := splitComments(com, ign)
	return result
}

func head1(blocks [][]string) [][]string {
	l := len(blocks)
	switch l {
	case 0, 1:
		return nil
	default:
		return [][]string{blocks[0]}
	}
}

func headN1(blocks [][]string) [][]string {
	l := len(blocks)
	if l == 0 {
		return nil
	}
	return blocks[0 : l-1]
}

func tail1(blocks [][]string) [][]string {
	l := len(blocks)
	switch l {
	case 0:
		return nil
	case 1:
		return blocks
	default:
		blocks[l-2] = nil
		return blocks[l-2:]
	}
}

func tailN1(blocks [][]string) [][]string {
	switch len(blocks) {
	case 0:
		return nil
	case 1:
		return blocks
	default:
		blocks[0] = nil
		return blocks
	}
}

func (p *printer) PreCommentX(n ast.Node, ign string, first bool) [][]string {
	comm := p.FindCommentBefore(n.Pos(), ign)
	if first {
		return tail1(comm)
	}
	return tailN1(comm)
}

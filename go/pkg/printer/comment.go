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

func (p *printer) Lookup(pos int) rune {
	if pos >= len(p.src) {
		return -1
	}
	return rune(p.src[pos])
}

func (p *printer) ReadCommentOrWhitespaceAfter(
	pos int, ignore string) (int, string) {

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
			if strings.IndexRune(ignore, c) == -1 {
				break READ
			}
			pos++
		}
	}
	return pos, string(p.src[start:pos])
}

func (p *printer) ReadCommentOrWhitespaceBefore(
	pos int, ignore string) (int, string) {

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
	return pos, string(p.src[pos+1 : end])
}

// Find comment lines in source beginning at position 'pos'
// up to first empty line.
// Ignore characters in 'ignore'.
// These are ignored and won't terminate sequences of comments.
// Returns
// 1. Comment in same line after 'pos'.
// 2. One or more comment lines in new line after pos.
/*
Examples:

host:h1 #1
,#2
host:h2;
=>
host:h1, #1
#2
host:h2,
;
---
host:h #c1
      ,#c2a
      ;#c2b
#c2c
=>
host:h1, #c1
#c2a
#c2b
;
#c2c
*/
//
func (p *printer) FindCommentAfter(pos int, ignore string) (string, [][]string) {

	var first string
	var result [][]string
	var block []string
	trailing := true
	for {
		end, com := p.ReadCommentOrWhitespaceAfter(pos, ignore)
		lines := strings.Split(com, "\n")

		// 'lines' is known to have at least one element.
		// Comment line is known to end with "\n", even at EOF.
		// (Has been added if missing.)
		// So, any comment would result in at least two lines.

		// Process all lines except last one.
		last := len(lines) - 1
		for _, line := range lines[:last] {
			// Check if line contains comment.
			if idx := strings.Index(line, "#"); idx != -1 {
				line = line[idx:] // Ignore leading whitespace
				if trailing {
					first = line
				} else {
					block = append(block, line)
				}
			} else {
				// Found empty line, separating blocks of comment lines.
				if block != nil || result == nil {
					result = append(result, block)
					block = nil
				}
			}
			trailing = false
		}

		// Ignore last line. It doesn't end with "\n"
		// and is known to be only whitespace.

		// To be ignored character follows.
		if strings.IndexRune(ignore, p.Lookup(end)) != -1 {
			pos = end + 1
			continue
		}
		return first, append(result, block)
	}
}

func (p *printer) PostComment(n ast.Node, ign string) (string, [][]string) {
	return p.FindCommentAfter(n.End(), ign)
}

func (p *printer) FindCommentBefore(pos int, ignore string) [][]string {

	var result [][]string
	var block []string

	start, com := p.ReadCommentOrWhitespaceBefore(pos, ignore)

	// Lookup previous character.
	// Check
	var prev rune
	if start > 0 {
		prev = p.Lookup(start - 1)
	} else {
		prev = '\n'
	}

	lines := strings.Split(com, "\n")
	// Ignore last line without trailing "\n".
	lines = lines[:len(lines)-1]
	// Ignore trailing comment or whitespace in first line.
	if prev != '\n' && len(lines) > 0 {
		lines = lines[1:]
	}
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx != -1 {
			// Line contains comment.
			block = append(block, line[idx:]) // Ignore leading whitespace
		} else {
			// Found empty line, separating blocks of comment lines.
			if block != nil {
				result = append(result, block)
				block = nil
			}
		}
	}

	return append(result, block)
}

func (p *printer) PreComment(n ast.Node) [][]string {
	return p.FindCommentBefore(n.Pos(), "")
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

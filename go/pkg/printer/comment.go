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

func (p *printer) ReadCommentOrWhitespace(pos int) (int, string) {
	start := pos
	for pos < len(p.src) {
		switch rune(p.src[pos]) {
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
			break
		}
	}
	return pos, string(p.src[start:pos])
}

func (p *printer) ReadCommentOrWhitespaceBefore(pos int) (int, string) {
	end := pos
	pos--
OUTER:
	for pos >= 0 {
		switch rune(p.src[pos]) {
		case ' ', '\t', '\n', '\r':
			// Whitespace
			pos--
		default:
			// Check backwards for comment.
			i := pos
			for {
				switch p.src[i] {
				case '#':
					pos = i - 1
					continue OUTER
				case '\n':
					break OUTER
				default:
					i--
					if i < 0 {
						break OUTER
					}
				}
			}
		}
	}
	return pos, string(p.src[pos+1 : end])
}

// Find comments in source beginning at position 'pos'.
// Ignore characters in 'ignore'.
// These are ignored and won't terminate sequences of comments.
// Blocks of comment lines are separated
// - by one or more empty lines or
// - first comment is on same line behind some token
//   and following comments are on separate lines.
// Returns
// 1. A slice of blocks of comments.
// - If a block is preceeded / succeeded by an empty line, an empty
//   block is prepended / appended.
// - Multiple empty lines without any comment are ignored.
//   In this case, return value ist nil.
// 2. Position of following token
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
func (p *printer) FindComment(pos int, ignore string) [][]string {

	var result [][]string
	var block []string
	trailing := true
	for {
		end, com := p.ReadCommentOrWhitespace(pos)
		lines := strings.Split(com, "\n")

		// 'lines' is known to have at least one element.
		// Comment line is known to end with "\n", even at EOF.
		// (Has been added by scanner if missing.)
		// So, any comment would result in at least two lines.

		// Process all lines except last one.
		last := len(lines) - 1
		for _, line := range lines[:last] {
			// Check if line contains comment.
			if i := strings.Index(line, "#"); i != -1 {
				block = append(block, line[i:]) // Ignore leading whitespace
			} else if trailing {
				block = append(block, "")
			} else {
				result = append(result, block)
				block = nil
			}
			trailing = false
		}

		// Process last line. It doesn't end with "\n".
		// This is known to be only whitespace.
		// Comment line is known to end with "\n", even at EOF.
		// (Has been added by scanner if missing.)

		// To be ignored character follows.
		if strings.IndexRune(ignore, p.Lookup(end)) != -1 {
			pos = end
			continue
		}
		return result
	}
}

func (p *printer) FindCommentBefore(pos int, ignore string) [][]string {

	var result [][]string
	var block []string

	for {
		start, com := p.ReadCommentOrWhitespaceBefore(pos)

		// Lookup previous character.
		var prev rune
		if start > 0 {
			prev = p.Lookup(start - 1)
		} else {
			prev = '\n'
		}

		lines := strings.Split(com, "\n")
		for i, line := range lines {
			if idx := strings.Index(line, "#"); idx != -1 {
				// Line contains comment.
				block = append(block, line[idx:]) // Ignore leading whitespace
			} else if !(i == 0 && prev != '\n') {
				// Found empty line, separating blocks of comment lines.
				if block != nil {
					result = append(result, block)
					block = nil
				}
			}
		}

		// Check previous ASCII character.
		if strings.IndexRune(ignore, prev) != -1 {
			pos = start - 1
			continue
		}
		return result
	}
}

func (p *printer) PreComment(n ast.Node) [][]string {
	return p.FindCommentBefore(n.Pos(), "")
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
	if l == 0 {
		return nil
	}
	return blocks[l-1:]
}

func tailN1(blocks [][]string) [][]string {
	l := len(blocks)
	if l == 0 {
		return nil
	}
	return blocks[1:]
}

func (p *printer) PreCommentX(n ast.Node, first bool) [][]string {
	comm := p.FindCommentBefore(n.Pos(), "")
	if first {
		return tail1(comm)
	}
	return tailN1(comm)
}

// Package scanner implements a scanner for source text of Netspoc
// policy language.  It takes a []byte as source which can then be
// tokenized through repeated calls to the Scan method.
//
package scanner

import (
	"fmt"
	//	"os"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// A Scanner holds the scanner's internal state while processing
// a given text. It can be allocated as part of another data
// structure but must be initialized via Init before use.
//
type Scanner struct {
	// immutable state
	src   []byte // source
	fname string // name of source file

	// scanning state
	ch       rune // current character
	offset   int  // character offset
	rdOffset int  // reading offset (position after current character)
}

// Read the next Unicode char into s.ch.
// s.ch < 0 means end-of-file.
//
func (s *Scanner) next() {
	if s.rdOffset < len(s.src) {
		s.offset = s.rdOffset
		r, w := rune(s.src[s.rdOffset]), 1
		switch {
		case r == 0:
			s.SyntaxErr("illegal character NUL")
		case r >= utf8.RuneSelf:
			// not ASCII
			r, w = utf8.DecodeRune(s.src[s.rdOffset:])
			if r == utf8.RuneError && w == 1 {
				s.SyntaxErr("illegal UTF-8 encoding")
			}
		}
		s.rdOffset += w
		s.ch = r
	} else {
		s.offset = len(s.src)
		s.ch = -1 // eof
	}
}

// Init prepares the scanner s to tokenize the text src by setting the
// scanner at the beginning of src.
//
// Calls to Scan will invoke the error handler err if they encounter a
// syntax error and err is not nil. Also, for each error encountered,
// the Scanner field ErrorCount is incremented by one.
//
// Note that Init may call err if there is an error in the first character
// of the file.
//
func (s *Scanner) Init(src []byte, fname string) {
	s.src = src
	s.fname = fname

	s.ch = ' '
	s.offset = 0
	s.rdOffset = 0

	s.next()
}

// Get number of current line.
// First line has number 1.
func (s *Scanner) currentLine() int {
	pos := 0
	line := 1
	for pos < s.offset {
		r, w := utf8.DecodeRune(s.src[pos:])
		pos += w
		if r == '\n' {
			line++
		}
	}
	return line
}

func (s *Scanner) context() string {
	pos := s.offset
	line := s.currentLine()
	c := fmt.Sprintf(" at line %d of %s, ", line, s.fname)
	if pos == len(s.src) {
		c += "at EOF"
	} else {
		sep := `[,;={} \t]*`
		ident := `[^ \t\n,;={}]*`
		pre := s.src[:pos]
		re := regexp.MustCompile(ident + sep + "$")
		m := re.FindSubmatch(pre)
		c += `near "` + string(m[0]) + "<--HERE-->"
		post := s.src[pos:]
		re = regexp.MustCompile("^" + sep + ident)
		m = re.FindSubmatch(post)
		c += string(m[0]) + `"`
	}
	return c
}

func (s *Scanner) SyntaxErr(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	msg = "Syntax error: " + msg + s.context()
	panic(msg)
	//	fmt.Fprintln(os.Stderr, msg)
	//	os.Exit(1)
}

func lower(ch rune) rune     { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }

func isLetter(ch rune) bool {
	return 'a' <= lower(ch) && lower(ch) <= 'z' ||
		ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

func isDigit(ch rune) bool {
	return isDecimal(ch) || ch >= utf8.RuneSelf && unicode.IsDigit(ch)
}

func isTokenChar(ch rune) bool {
	if isLetter(ch) || isDigit(ch) {
		return true
	}
	switch ch {
	case '-', '_', '.', ':', '/', '@':
		return true
	default:
		return false
	}
}

func (s *Scanner) skipWhitespace() {
	for {
		switch s.ch {
		case ' ', '\t', '\n', '\r':
			s.next()
		case '#':
			// Skip comment.
			s.ToEOL()
		default:
			return
		}
	}
}

func (s *Scanner) scan(check func(rune) bool) (int, string) {
	s.skipWhitespace()

	// current token start
	pos := s.offset

	// determine token value
	ch := s.ch
	s.next()
	if check(ch) {
		for check(s.ch) {
			s.next()
		}
	}
	return pos, string(s.src[pos:s.offset])
}

// Token scans the next token and returns the token position and the
// token literal string. The source end is indicated by "".
//
func (s *Scanner) Token() (int, string) {
	pos, tok := s.scan(isTokenChar)
	// Token may end with '['.
	if s.ch == '[' {
		s.next()
		tok = tok + "["
	}
	return pos, tok
}

// Number scans the next numeric token consisting solely of ASCII
// digits. It returns the token position and the token literal
// string. The source end is indicated by "".
//
func (s *Scanner) Number() (int, string) {
	return s.scan(isDecimal)
}

func (s *Scanner) ToEOL() (int, string) {
	pos := s.offset
	for s.ch != '\n' && s.ch >= 0 {
		s.next()
	}
	return pos, string(s.src[pos:s.offset])
}

func (s *Scanner) ToEOLorComment() (int, string) {
	pos := s.offset
	for s.ch != '\n' && s.ch != '#' && s.ch >= 0 {
		s.next()
	}
	return pos, string(s.src[pos:s.offset])
}

func (s *Scanner) Lookup(pos int) rune {
	if pos >= len(s.src) {
		return -1
	}
	return rune(s.src[pos])
}

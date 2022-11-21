// Package scanner implements a scanner for source text of Netspoc
// policy language.  It takes a []byte as source which can then be
// tokenized through repeated calls to the Scan method.
package scanner

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// An AbortHandler must be provided to Scanner.Init. If a syntax error is
// encountered, the handler is called after error message has been shown.
type AbortHandler func(e error)

// A Scanner holds the scanner's internal state while processing
// a given text. It can be allocated as part of another data
// structure but must be initialized via Init before use.
type Scanner struct {
	// immutable state
	src   []byte // source
	fname string // name of source file
	abort AbortHandler

	// scanning state
	ch       rune // current character
	offset   int  // character offset
	rdOffset int  // reading offset (position after current character)
}

// Read the next Unicode char into s.ch.
// s.ch < 0 means end-of-file.
func (s *Scanner) next() {
	if s.rdOffset < len(s.src) {
		s.offset = s.rdOffset
		r, w := rune(s.src[s.rdOffset]), 1
		switch {
		case r == 0:
			s.syntaxErr("illegal character NUL")
		case r >= utf8.RuneSelf:
			// not ASCII
			r, w = utf8.DecodeRune(s.src[s.rdOffset:])
			if r == utf8.RuneError {
				s.syntaxErr("illegal UTF-8 encoding")
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
// Calls to Scan will invoke the abort handler abort if they encounter a
// syntax error.
//
// Note that Init may call abort if there is an error in the first character
// of the file.
func (s *Scanner) Init(src []byte, fname string, ah AbortHandler) {
	s.src = src
	s.fname = fname
	s.abort = ah

	s.ch = ' '
	s.offset = 0
	s.rdOffset = 0

	s.next()
}

// Get number of current line.
// First line has number 1.
func (s *Scanner) currentLine(offset int) int {
	pos := 0
	line := 1
	if offset == len(s.src) && s.src[len(s.src)-1] == '\n' {
		line--
	}
	for pos < offset {
		r := s.src[pos]
		pos++
		if r == '\n' {
			line++
		}
	}
	return line
}

func (s *Scanner) context(offset int) string {
	pos := offset
	line := s.currentLine(offset)
	c := fmt.Sprintf(" at line %d of %s, ", line, s.fname)
	if pos == len(s.src) {
		c += "at EOF"
	} else {
		sep := `[,;={} \t]*`
		ident := `[^ \t\n,;={}]*`
		pre := s.src[:pos]
		re := regexp.MustCompile(ident + sep + "$")
		m := re.FindSubmatch(pre)
		c += `near "` + string(m[0]) + "--HERE-->"
		post := s.src[pos:]
		re = regexp.MustCompile("^" + sep + ident)
		m = re.FindSubmatch(post)
		c += string(m[0]) + `"`
	}
	return c
}

func (s *Scanner) SyntaxErr(offset int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	msg = msg + s.context(offset)
	s.abort(errors.New(msg))
}

func (s *Scanner) syntaxErr(format string, args ...interface{}) {
	s.SyntaxErr(s.offset, format, args...)
}
func lower(ch rune) rune     { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }

func isLetter(ch rune) bool {
	return 'a' <= lower(ch) && lower(ch) <= 'z' || ch == '_' ||
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
	case '-', '.', ':', '/', '@':
		return true
	default:
		return false
	}
}

// Take "-", "/" and ":" as separator.
func isProtoTokenChar(ch rune) bool {
	if isLetter(ch) || isDigit(ch) {
		return true
	}
	switch ch {
	case '.', '@':
		return true
	default:
		return false
	}
}

// Take "-" as separator.
func isIPRangeTokenChar(ch rune) bool {
	if isLetter(ch) || isDigit(ch) {
		return true
	}
	switch ch {
	case '.', ':', '/', '@':
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

func (s *Scanner) scan(check func(rune) bool) (int, bool, string) {
	s.skipWhitespace()

	// current token start
	pos := s.offset

	// determine token value
	ch := s.ch
	isSeparator := true
	s.next()
	if check(ch) {
		isSeparator = false
		for check(s.ch) {
			s.next()
		}
	}
	return pos, isSeparator, string(s.src[pos:s.offset])
}

// Token scans the next token and returns the token position and the
// token literal string. The source end is indicated by "".
func (s *Scanner) Token() (int, bool, string) {
	pos, isSep, tok := s.scan(isTokenChar)
	// Token may end with '['.
	if !isSep && s.ch == '[' {
		s.next()
		tok = tok + "["
	}
	return pos, isSep, tok
}

func (s *Scanner) ProtoToken() (int, bool, string) {
	return s.scan(isProtoTokenChar)
}

func (s *Scanner) IPRangeToken() (int, bool, string) {
	return s.scan(isIPRangeTokenChar)
}

func (s *Scanner) TokenToSemicolon() (int, bool, string) {
	return s.scan(func(ch rune) bool {
		switch ch {
		case ';', '\n', '#', -1:
			return false
		default:
			return true
		}
	})
}

func (s *Scanner) TokenToComma() (int, bool, string) {
	return s.scan(func(ch rune) bool {
		switch ch {
		case ',', ';', '\n', '#', ' ', '\t', '\r', '"', '\'', -1:
			return false
		default:
			return true
		}
	})
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

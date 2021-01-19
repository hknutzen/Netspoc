package testdata

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

type Descr struct {
	Title    string
	Input    string
	Option   string
	Param    string
	Output   string
	Warning  string
	Error    string
	ShowDiag bool
	Todo     bool
}

// State
// Textblocks holds key/value pairs defined by
// =VAR= name
// ...text lines ...
// =END=
// found during parsing
type state struct {
	src        []byte
	rest       []byte
	textblocks map[string]string
}

// ParseFile parses the named file as a list of test descriptions.
func ParseFile(file string) ([]*Descr, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	s := new(state)
	s.src = data
	s.rest = data
	s.textblocks = make(map[string]string)
	return s.parse()
}

func (s *state) currentLine() int {
	return 1 + bytes.Count(s.src[0:len(s.src)-len(s.rest)], []byte("\n"))
}

func (s *state) parse() ([]*Descr, error) {
	var result []*Descr
	var d *Descr
	var seen map[string]bool
	add := func() error {
		if d == nil {
			return errors.New("missing =TITLE= in first test")
		}
		if d.Input == "" {
			return fmt.Errorf("missing =INPUT= in test with =TITLE=%s", d.Title)
		}
		if d.Output == "" && d.Warning == "" && d.Error == "" {
			return fmt.Errorf(
				"missing =OUTPUT|WARNING|ERROR= in test with =TITLE=%s", d.Title)
		}
		if d.Error != "" && (d.Output != "" || d.Warning != "") {
			return fmt.Errorf(
				"must not define =ERROR= together with =OUTPUT= or =WARNING="+
					" in test with =TITLE=%s", d.Title)
		}
		result = append(result, d)
		return nil
	}
	for {
		name, err := s.readDef()
		if err != nil {
			return nil, err
		}
		switch name {
		case "":
			err := add()
			return result, err
		case "TITLE":
			if d != nil {
				err := add()
				if err != nil {
					return nil, err
				}
			}
			text, err := s.readText()
			if err != nil {
				return nil, err
			}
			d = new(Descr)
			d.Title = strings.TrimSuffix(text, "\n")
			seen = make(map[string]bool)
		case "VAR":
			if err := s.varDef(); err != nil {
				return nil, err
			}
		case "SUBST":
			if err := s.substDef(d); err != nil {
				return nil, err
			}
		default:
			if d == nil {
				return nil, errors.New("expected =TITLE=")
			}
			if seen[name] {
				return nil, fmt.Errorf(
					"found multiple =%s= in test with =TITLE=%s", name, d.Title)
			}
			text, err := s.readText()
			if err != nil {
				return nil, err
			}
			switch name {
			case "INPUT":
				d.Input = text
			case "OPTION":
				d.Option = strings.TrimSuffix(text, "\n")
			case "PARAM":
				d.Param = strings.TrimSuffix(text, "\n")
			case "OUTPUT":
				d.Output = text
			case "WARNING":
				d.Warning = text
			case "ERROR":
				d.Error = text
			case "SHOW_DIAG":
				d.ShowDiag = true
			case "TODO":
				d.Todo = true
			default:
				return nil, fmt.Errorf(
					"unexpected =%s= in test with =TITLE=%s", name, d.Title)
			}
			seen[name] = true
		}
	}
	return result, nil
}

func (s *state) readDef() (string, error) {
	var line string
	for {
		// Skip empty lines and comments
		idx := bytes.IndexByte(s.rest, byte('\n'))
		if idx == -1 {
			line = string(s.rest)
		} else {
			line = string(s.rest[:idx])
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			if idx == -1 {
				s.rest = s.rest[len(s.rest):]
				return "", nil
			} else {
				s.rest = s.rest[idx+1:]
				continue
			}
		} else {
			break
		}
	}
	name, err := s.checkDef(line)
	if err == nil {
		s.rest = s.rest[len(name)+2:]
	}
	return name, err
}

func (s *state) checkDef(line string) (string, error) {
	if line[0] == '=' {
		idx := strings.IndexByte(line[1:], byte('='))
		if idx != -1 {
			return line[1 : idx+1], nil
		}
	}
	nr := s.currentLine()
	return "", fmt.Errorf("expected token '=...=' at line %d: %s", nr, line)
}

func (s *state) substDef(d *Descr) error {
	line, err := s.getLine()
	if err != nil {
		return err
	}
	s.rest = s.rest[len(line):]
	line = strings.TrimSpace(line)
	parts := strings.Split(line[1:], line[0:1])
	if len(parts) != 3 || parts[2] != "" {
		return errors.New("invalid substitution: " + line)
	}
	if d == nil || d.Input == "" {
		return fmt.Errorf("=SUBST=%s must follow after =INPUT=", line)
	}
	d.Input = strings.ReplaceAll(d.Input, parts[0], parts[1])
	return nil
}

func (s *state) varDef() error {
	name, err := s.readVarName()
	if err != nil {
		return err
	}
	s.textblocks[name], err = s.readText()
	return err
}

func (s *state) readVarName() (string, error) {
	line, err := s.getLine()
	if err != nil {
		return "", err
	}
	s.rest = s.rest[len(line)-1:] // don't skip trailing newline
	name := strings.TrimSpace(line)
	for _, ch := range name {
		if !(isLetter(ch) || isDecimal(ch)) {
			return "", errors.New("invalid name after =VAR=: " + name)
		}
	}
	return name, nil
}

func lower(ch rune) rune     { return ('a' - 'A') | ch }
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }

func isLetter(ch rune) bool {
	return 'a' <= lower(ch) && lower(ch) <= 'z' || ch == '_'
}

func (s *state) readText() (string, error) {
	// Check for single line
	line, err := s.getLine()
	if err != nil {
		return "", err
	}
	s.rest = s.rest[len(line):]
	line = strings.TrimSpace(line)
	if line != "" {
		result, err := s.doVarSubst(line)
		if err != nil {
			return "", err
		}
		if !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
		return result, nil
	}
	// Read multiple lines up to start of next definition
	text := s.rest
	size := 0
	for {
		line, err := s.getLine()
		if err != nil {
			return "", err
		}
		if name, err := s.checkDef(line); err == nil {
			if name == "END" {
				s.rest = s.rest[len("=END="):]
			}
			return s.doVarSubst(string(text[:size]))
		}
		s.rest = s.rest[len(line):]
		size += len(line)
	}
}

// Substitute occurrences of ${name} with corresponding value.
func (s *state) doVarSubst(text string) (string, error) {
	for name, val := range s.textblocks {
		text = strings.ReplaceAll(text, "${"+name+"}", val)
	}
	return text, nil
}

func (s *state) getLine() (string, error) {
	idx := bytes.IndexByte(s.rest, byte('\n'))
	if idx == -1 {
		return "", errors.New("unexpected end of file")
	}
	return string(s.rest[:idx+1]), nil
}

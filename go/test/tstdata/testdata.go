package tstdata

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Descr struct {
	Title     string
	Setup     string
	Input     string
	ReusePrev string
	Options   string
	FOption   string
	Job       string
	Param     string
	Params    string
	Output    string
	Warning   string
	Error     string
	ShowDiag  bool
	Todo      bool
	WithOutD  bool
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

func GetFiles(dataDir string) []string {
	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	var names []string
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".t") {
			name = path.Join(dataDir, name)
			names = append(names, name)
		}
	}
	return names
}

// ParseFile parses the named file as a list of test descriptions.
func ParseFile(file string) ([]*Descr, error) {
	data, err := os.ReadFile(file)
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
		if d.Error != "" && d.Warning != "" {
			return fmt.Errorf(
				"must not define =ERROR= together with =WARNING="+
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
		case "": // EOF
			err := add()
			return result, err
		case "TITLE": // Next entry.
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
			d.Title = text
			seen = make(map[string]bool)
		case "VAR":
			if err := s.varDef(); err != nil {
				return nil, err
			}
		case "SUBST":
			if err := s.substDef(d); err != nil {
				return nil, err
			}
		case "DATE":
			if err := s.dateDef(d); err != nil {
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
			case "SETUP":
				d.Setup = text
			case "INPUT":
				d.Input = text
			case "REUSE_PREV":
				d.ReusePrev = text
			case "OPTIONS":
				d.Options = text
			case "FOPTION":
				d.FOption = text
			case "JOB":
				d.Job = text
			case "PARAM":
				d.Param = text
			case "PARAMS":
				d.Params = text
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
			case "WITH_OUTDIR":
				d.WithOutD = true
			default:
				return nil, fmt.Errorf(
					"unexpected =%s= in test with =TITLE=%s", name, d.Title)
			}
			seen[name] = true
		}
	}
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
				// Found EOF.
				return "", nil
			} else {
				s.rest = s.rest[idx+1:]
				continue
			}
		} else {
			break
		}
	}
	name := s.checkDef(line)
	if name == "" {
		nr := s.currentLine()
		return "", fmt.Errorf("expected token '=...=' at line %d: %s", nr, line)
	}
	s.rest = s.rest[len(name)+2:]
	return name, nil
}

func (s *state) checkDef(line string) string {
	if line[0] != '=' {
		return ""
	}
	idx := strings.Index(line[1:], "=")
	if idx == -1 {
		return ""
	}
	name := line[1 : idx+1]
	if isName(name) {
		return name
	}
	return ""
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
	text, err := s.readText()
	if err != nil {
		return err
	}
	text = strings.TrimSuffix(text, "\n")
	s.textblocks[name] = text
	return nil
}

func (s *state) dateDef(d *Descr) error {
	line, err := s.getLine()
	if err != nil {
		return err
	}
	s.rest = s.rest[len(line):]
	line = strings.TrimSpace(line)
	days, err := strconv.Atoi(line)
	date := time.Now().AddDate(0, 0, days)
	s.textblocks["DATE"] = date.Format("2006-01-02")
	return nil
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

func isName(n string) bool {
	for _, ch := range n {
		if !(isLetter(ch) || isDecimal(ch)) {
			return false
		}
	}
	return true
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
		return s.doVarSubst(line), nil
	}
	// Read multiple lines up to start of next definition
	text := s.rest
	size := 0
	for {
		line, err := s.getLine()
		if err != nil {
			return "", err
		}
		if name := s.checkDef(line); name != "" {
			if name == "END" {
				s.rest = s.rest[len("=END="):]
			}
			return s.doVarSubst(string(text[:size])), nil
		}
		s.rest = s.rest[len(line):]
		size += len(line)
	}
}

// Substitute occurrences of ${name} with corresponding value.
func (s *state) doVarSubst(text string) string {
	for name, val := range s.textblocks {
		text = strings.ReplaceAll(text, "${"+name+"}", val)
	}
	return text
}

func (s *state) getLine() (string, error) {
	idx := bytes.IndexByte(s.rest, byte('\n'))
	if idx == -1 {
		return string(s.rest), nil
	}
	return string(s.rest[:idx+1]), nil
}

// Fill input directory with file(s).
// Parts of input are marked by single lines of dashes
// followed by a filename.
// If no filename is given, preceeding filename is reused.
// If no markers are given, a single file named INPUT is used.
func PrepareInDir(inDir, input string) {
	if input == "NONE" {
		input = ""
	}
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(input, -1)

	write := func(pName, data string) {
		if path.IsAbs(pName) {
			log.Fatalf("Unexpected absolute path '%s'", pName)
		}
		dir, file := path.Split(pName)
		fullDir := path.Join(inDir, dir)
		if err := os.MkdirAll(fullDir, 0755); err != nil {
			log.Fatal(err)
		}
		fullPath := path.Join(fullDir, file)
		if err := os.WriteFile(fullPath, []byte(data), 0644); err != nil {
			log.Fatal(err)
		}
	}

	// No filename
	if il == nil {
		write("INPUT", input)
	} else if il[0][0] != 0 {
		log.Fatal("Missing file marker in first line")
	} else {
		for i, p := range il {
			marker := input[p[0] : p[1]-1] // without trailing "\n"
			pName := strings.Trim(marker, "- ")
			start := p[1]
			end := len(input)
			if i+1 < len(il) {
				end = il[i+1][0]
			}
			data := input[start:end]
			write(pName, data)
		}
	}
}

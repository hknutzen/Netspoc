package astset

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"strings"
)

type State struct {
	fileNodes [][]ast.Toplevel
	sources   [][]byte
	files     []string
	changed   map[string]bool
}

func Read(netspocPath string) (*State, error) {
	s := new(State)
	s.changed = make(map[string]bool)
	err := filetree.Walk(netspocPath, func(input *filetree.Context) error {
		source := []byte(input.Data)
		path := input.Path
		nodes, err := parser.ParseFile(source, path)
		if err != nil {
			return err
		}
		s.fileNodes = append(s.fileNodes, nodes)
		s.files = append(s.files, path)
		s.sources = append(s.sources, source)
		return nil
	})
	return s, err
}

func (s *State) Changed() []string {
	var result []string
	for _, path := range s.files {
		if s.changed[path] {
			result = append(result, path)
		}
	}
	return result
}

func (s *State) Print() {
	for i, path := range s.files {
		if s.changed[path] {
			p := printer.File(s.fileNodes[i], s.sources[i])
			err := fileop.Overwrite(path, p)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (s *State) getFileIndex(file string) int {
	idx := -1
	for i, f := range s.files {
		if f == file {
			idx = i
		}
	}
	if idx == -1 {
		idx = len(s.files)
		s.files = append(s.files, file)
		s.fileNodes = append(s.fileNodes, nil)
		s.sources = append(s.sources, nil)
	}
	return idx
}

func (s *State) GetFileNodes(file string) []ast.Toplevel {
	idx := s.getFileIndex(file)
	return s.fileNodes[idx]
}

func (s *State) Modify(f func(ast.Toplevel) bool) bool {
	someModified := false
	for i, nodes := range s.fileNodes {
		modified := false
		for _, n := range nodes {
			if f(n) {
				modified = true
			}
		}
		if modified {
			s.changed[s.files[i]] = true
			someModified = true
		}
	}
	return someModified
}

func (s *State) ModifyObj(name string, f func(ast.Toplevel)) error {
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if name == toplevel.GetName() {
			f(toplevel)
			return true
		}
		return false
	})
	if !found {
		return fmt.Errorf("Can't find %s", name)
	}
	return nil
}

func (s *State) CreateToplevel(fullName, file string, n ast.Toplevel) {
	idx := s.getFileIndex(file)
	nodes := s.fileNodes[idx]
	cp := make([]ast.Toplevel, 0, len(nodes)+1)
	inserted := false
	typ, name := getTypeName(fullName)
	nLower := strings.ToLower(name)
	for i, toplevel := range nodes {
		typ2, name2 := getTypeName(toplevel.GetName())
		if typ2 == typ && strings.ToLower(name2) > nLower {
			cp = append(cp, n)
			cp = append(cp, nodes[i:]...)
			inserted = true
			break
		}
		cp = append(cp, toplevel)
	}
	if !inserted {
		cp = append(cp, n)
	}
	s.fileNodes[idx] = cp
	s.changed[file] = true
}

func (s *State) DeleteToplevel(name string) error {
	found := false
	for i, nodes := range s.fileNodes {
		cp := make([]ast.Toplevel, 0, len(nodes))
		for _, toplevel := range nodes {
			if name == toplevel.GetName() {
				found = true
			} else {
				cp = append(cp, toplevel)
			}
		}
		if found {
			s.fileNodes[i] = cp
			s.changed[s.files[i]] = true
			return nil
		}
	}
	return fmt.Errorf("Can't find %s", name)
}

func getTypeName(v string) (string, string) {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return v, ""
	}
	return parts[0], parts[1]
}

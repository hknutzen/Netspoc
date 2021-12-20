package astset

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
)

type State struct {
	astFiles []*ast.File
	base     string
	files    []string
	changed  map[string]bool
}

func Read(netspocBase string) (*State, error) {
	s := new(State)
	s.changed = make(map[string]bool)
	s.base = netspocBase
	err := filetree.Walk(netspocBase, func(input *filetree.Context) error {
		source := []byte(input.Data)
		path := input.Path
		aF, err := parser.ParseFile(source, path, parser.ParseComments)
		if err != nil {
			return err
		}
		s.astFiles = append(s.astFiles, aF)
		s.files = append(s.files, path)
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
			p := printer.File(s.astFiles[i])
			err := fileop.Overwrite(path, p)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (s *State) getFileIndex(file string) int {
	file = path.Clean(file)
	file = path.Join(s.base, file)
	idx := -1
	for i, f := range s.files {
		if f == file {
			idx = i
		}
	}
	// New file is added.
	if idx == -1 {
		// Create missing sub directory.
		d := path.Dir(file)
		if err := os.MkdirAll(d, os.ModePerm); err != nil {
			panic(err)
		}
		idx = len(s.files)
		s.files = append(s.files, file)
		s.astFiles = append(s.astFiles, new(ast.File))
	}
	return idx
}

func (s *State) Modify(f func(ast.Toplevel) bool) bool {
	someModified := false
	for i, aF := range s.astFiles {
		modified := false
		for _, n := range aF.Nodes {
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

func (s *State) ModifyObj(name string, f func(ast.Toplevel) error) error {
	var err error
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if name == toplevel.GetName() {
			if err2 := f(toplevel); err2 != nil {
				err = err2
			}
			return true
		}
		return false
	})
	if !found {
		return fmt.Errorf("Can't find %s", name)
	}
	return err
}

func (s *State) CreateToplevel(file string, n ast.Toplevel) {
	idx := s.getFileIndex(file)
	aF := s.astFiles[idx]
	cp := make([]ast.Toplevel, 0, len(aF.Nodes)+1)
	inserted := false
	typ, name := getTypeName(n.GetName())
	nLower := strings.ToLower(name)
	for i, toplevel := range aF.Nodes {
		typ2, name2 := getTypeName(toplevel.GetName())
		if typ2 == typ && strings.ToLower(name2) > nLower {
			cp = append(cp, n)
			cp = append(cp, aF.Nodes[i:]...)
			inserted = true
			break
		}
		cp = append(cp, toplevel)
	}
	if !inserted {
		cp = append(cp, n)
	}
	s.astFiles[idx].Nodes = cp
	s.changed[s.files[idx]] = true
}

func (s *State) DeleteToplevel(name string) error {
	found := false
	for i, aF := range s.astFiles {
		cp := make([]ast.Toplevel, 0, len(aF.Nodes))
		for _, toplevel := range aF.Nodes {
			if name == toplevel.GetName() {
				found = true
			} else {
				cp = append(cp, toplevel)
			}
		}
		if found {
			s.astFiles[i].Nodes = cp
			s.changed[s.files[i]] = true
			return nil
		}
	}
	return fmt.Errorf("Can't find %s", name)
}

func (s *State) RemoveServiceFromOverlaps(name string) {
	for _, aF := range s.astFiles {
		for _, toplevel := range aF.Nodes {
			if n, ok := toplevel.(*ast.Service); ok {
				if overlaps := n.GetAttr("overlaps"); overlaps != nil {
					overlaps.Remove(name)
					if len(overlaps.ValueList) == 0 {
						n.RemoveAttr("overlaps")
					}
				}
			}
		}
	}
}

func (s *State) TransposeService(name string) error {
	var err error
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if n, ok := toplevel.(*ast.Service); ok {
			if name == n.GetName() {
				if n.Foreach {
					return false
				}
				srcelements := n.Rules[0].Src.Elements
				dstelements := n.Rules[0].Dst.Elements
				userelements := n.User.Elements
				if len(n.Rules) > 1 {
					err = fmt.Errorf("Can't transpose service: multiple rules present.")
					return false

				}
				// If source and destination are user no transformation needed
				if len(srcelements) == 1 && len(dstelements) == 1 &&
					srcelements[0].GetType() == "user" && dstelements[0].GetType() == "user" {
					err = fmt.Errorf("Can't transpose service: src and dst are user.")
					return false
				}
				if len(srcelements) == 1 {
					if srcelements[0].GetType() == "user" {
						n.Rules[0].Src.Elements = userelements
						n.Rules[0].Dst.Elements = srcelements
						n.User.Elements = dstelements
						return true
					}
				}
				if len(dstelements) == 1 {
					if dstelements[0].GetType() == "user" {
						n.Rules[0].Src.Elements = dstelements
						n.Rules[0].Dst.Elements = userelements
						n.User.Elements = srcelements
						return true
					}
				}
			}
		}
		err = fmt.Errorf("Can't find service %s", name)
		return false
	})

	if found {
		return nil
	} else {
		return err
	}
}

func getTypeName(v string) (string, string) {
	i := strings.Index(v, ":")
	return v[:i], v[i+1:]
}

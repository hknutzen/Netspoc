package astset

import (
	"fmt"
	"io"
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

func Read(netspocBase string, v6 bool) (*State, error) {
	s := new(State)
	s.changed = make(map[string]bool)
	s.base = netspocBase
	err := filetree.Walk(netspocBase, v6, func(input *filetree.Context) error {
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

func (s *State) ShowChanged(stderr io.Writer, quiet bool) {
	if !quiet {
		for _, file := range s.Changed() {
			fmt.Fprintf(stderr, "Changed %s\n", file)
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

func (s *State) Replace(f func(*ast.Toplevel) bool) bool {
	someModified := false
	for i, aF := range s.astFiles {
		modified := false
		for i := range aF.Nodes {
			if f(&aF.Nodes[i]) {
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

func (s *State) Modify(f func(ast.Toplevel) bool) bool {
	return s.Replace(func(ptr *ast.Toplevel) bool {
		return f(*ptr)
	})
}

func (s *State) ModifyObj(name string, f func(ast.Toplevel)) error {
	var err error
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
	return err
}

func (s *State) FindToplevel(name string) ast.Toplevel {
	var result ast.Toplevel
	s.Modify(func(t ast.Toplevel) bool {
		if name == t.GetName() {
			result = t
		}
		return false
	})
	return result
}

func (s *State) SetModified(name string) {
	s.Modify(func(t ast.Toplevel) bool { return name == t.GetName() })
}

func (s *State) AddTopLevel(n ast.Toplevel) {
	// Netspoc config is given in single file, add new node to this file.
	if len(s.files) == 1 && s.files[0] == s.base {
		s.CreateToplevel(s.base, n)
	}
	file := "API"
	if typ, name, found := strings.Cut(n.GetName(), ":"); found {
		switch typ {
		case "owner":
			file = "owner"
			if strings.HasPrefix(name, "DA_TOKEN_") {
				file += "-token"
			}
		case "service":
			file = "rule"
			if !fileop.IsDir(file) {
				// Ignore error, is recognized later, when file can't be written.
				os.Mkdir(file, 0777)
			}
			if len(name) > 0 {
				s0 := strings.ToUpper(name[0:1])
				c0 := s0[0]
				if 'A' <= c0 && c0 <= 'Z' || '0' <= c0 && c0 <= '9' {
					file = path.Join(file, s0)
					break
				}
			}
			file = path.Join(file, "other")
		}
	}
	s.CreateToplevel(file, n)
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
	typ, _, _ := strings.Cut(name, ":")
	switch typ {
	case "service":
		s.RemoveFromToplevelAttr("service:", "overlaps", name)
		s.RemoveFromToplevelAttr("service:", "identical_body", name)
	case "network":
		s.RemoveFromToplevelAttr("network:", "subnet_of", name)
	}
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

func (s *State) DeleteHost(name string) error {
	netName := ""
	if strings.HasPrefix(name, "host:id:") {
		// ID host is extended by network name: host:id:a.b@c.d.net_name
		parts := strings.Split(name, ".")
		netName = "network:" + parts[len(parts)-1]
		name = strings.Join(parts[:len(parts)-1], ".")
	}
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		modified := false
		if n, ok := toplevel.(*ast.Network); ok {
			if netName != "" && netName != n.Name {
				return false
			}
			j := 0
			for _, a := range n.Hosts {
				if a.Name == name {
					modified = true
				} else {
					n.Hosts[j] = a
					j++
				}
			}
			n.Hosts = n.Hosts[:j]
		}
		return modified
	})
	if found {
		return nil
	}
	return fmt.Errorf("Can't find %s", name)
}

func (s *State) DeleteUnmanagedLoopbackInterface(name string) {
	name = name[len("interface:"):]
	rName, iName, _ := strings.Cut(name, ".")
	iName = "interface:" + iName
	rName = "router:" + rName
	s.Modify(func(toplevel ast.Toplevel) bool {
		modified := false
		if r, ok := toplevel.(*ast.Router); ok {
			if r.Name != rName || r.GetAttr("managed") != nil {
				return false
			}
			j := 0
			for _, a := range r.Interfaces {
				if a.Name == iName &&
					(a.GetAttr("loopback") != nil || a.GetAttr("vip") != nil) {
					modified = true
				} else {
					r.Interfaces[j] = a
					j++
				}
			}
			r.Interfaces = r.Interfaces[:j]
		}
		return modified
	})
}

func (s *State) RemoveFromToplevelAttr(typ, attr, name string) {
	s.Modify(func(top ast.Toplevel) bool {
		if n, ok := top.(ast.ToplevelWithAttr); ok &&
			strings.HasPrefix(top.GetName(), typ) {

			if a := n.GetAttr(attr); a != nil {
				if oLen := len(a.ValueList); oLen > 0 {
					a.Remove(name)
					nLen := len(a.ValueList)
					if nLen == 0 {
						n.RemoveAttr(attr)
					}
					return nLen < oLen
				}
			}
		}
		return false
	})
}

func getTypeName(v string) (string, string) {
	i := strings.Index(v, ":")
	return v[:i], v[i+1:]
}

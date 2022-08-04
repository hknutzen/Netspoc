package api

/*
Process jobs of Netspoc-API

COPYRIGHT AND DISCLAIMER
(c) 2022 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc-API

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
)

type state struct {
	*astset.State
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR JOB ...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	// Argument processing
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		return 1
	}
	netspocPath := args[0]

	// Initialize config.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, netspocPath)

	showErr := func(format string, args ...interface{}) {
		fmt.Fprintf(d.Stderr, "Error: "+format+"\n", args...)
	}

	s := new(state)
	var err error
	s.State, err = astset.Read(netspocPath, cnf.IPV6)
	if err != nil {
		// Text of this error message is checked in cvs-worker1 of Netspoc-API.
		showErr("While reading netspoc files: %s", err)
		return 1
	}
	for _, path := range args[1:] {
		if err := s.doJobFile(path); err != nil {
			showErr("%s", err)
			return 1
		}
	}
	s.ShowChanged(d.Stderr, cnf.Quiet)
	s.Print()
	return 0
}

type job struct {
	Method string
	Params json.RawMessage
	Crq    string
}

var handler = map[string]func(*state, *job) error{
	"add":             (*state).patch,
	"delete":          (*state).patch,
	"set":             (*state).patch,
	"create_toplevel": (*state).createToplevel,
	"delete_toplevel": (*state).deleteToplevel,
	"create_host":     (*state).createHost,
	"modify_host":     (*state).modifyHost,
	"create_owner":    (*state).createOwner,
	"modify_owner":    (*state).modifyOwner,
	"delete_owner":    (*state).deleteOwner,
	"add_to_group":    (*state).addToGroup,
}

func (s *state) doJobFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	j := new(job)
	if err := json.Unmarshal(data, j); err != nil {
		return fmt.Errorf("In JSON file %s: %s", path, err)
	}
	// Check once if j.Params is correct JSON.
	if len(j.Params) == 0 {
		return fmt.Errorf("Missing \"params\" in JSON file %s", path)
	}
	var dummy map[string]interface{}
	if err := json.Unmarshal(j.Params, &dummy); err != nil {
		return fmt.Errorf("In \"params\" of JSON file %s: %s", path, err)
	}
	return s.doJob(j)
}

func (s *state) doJob(j *job) error {
	m := j.Method
	if m == "multi_job" {
		return s.multiJob(j)
	}
	if fn, found := handler[m]; found {
		return fn(s, j)
	} else {
		return fmt.Errorf("Unknown method '%s'", m)
	}
}

func (s *state) multiJob(j *job) error {
	var p struct {
		Jobs []*job
	}
	getParams(j, &p)
	for _, sub := range p.Jobs {
		if err := s.doJob(sub); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) createHost(j *job) error {
	var p struct {
		Network string
		Name    string
		IP      string
		Mask    string
		Owner   string
	}
	getParams(j, &p)
	network := p.Network
	host := p.Name
	ip := p.IP
	owner := p.Owner

	attr := "ip"
	ip1 := ip
	// Use attribute "range" when IP1-IP2 range is given.
	// Use IP1 when searching corresponding network.
	if i := strings.Index(ip, "-"); i != -1 {
		attr = "range"
		ip1 = ip[:i]
	}

	// Search network matching given ip and mask.
	var netAddr string
	if network == "[auto]" {
		i := net.ParseIP(ip1).To4()
		if i == nil {
			return fmt.Errorf("Invalid IP address: '%s'", ip1)
		}
		m := net.IPMask(net.ParseIP(p.Mask).To4())
		_, bits := m.Size()
		if bits == 0 {
			return fmt.Errorf("Invalid IP mask: '%s'", p.Mask)
		}
		netAddr = (&net.IPNet{IP: i.Mask(m), Mask: m}).String()
		network = ""
	} else {
		network = "network:" + network
	}
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if n, ok := toplevel.(*ast.Network); ok {
			if network != "" && network == n.Name ||
				netAddr != "" && netAddr == n.GetAttr1("ip") {

				// Don't add owner, if already present at network.
				if owner == n.GetAttr1("owner") {
					owner = ""
				}

				// Add host.
				h := &ast.Attribute{Name: "host:" + host}
				h.ComplexValue = append(h.ComplexValue, ast.CreateAttr1(attr, ip))
				if owner != "" {
					h.ComplexValue =
						append(h.ComplexValue, ast.CreateAttr1("owner", owner))
				}
				n.Hosts = append(n.Hosts, h)

				// Sort list of hosts.
				n.Order()
				return true
			}
		}
		return false
	})
	if !found {
		if network != "" {
			return fmt.Errorf("Can't find '%s'", network)
		} else {
			return fmt.Errorf("Can't find network with 'ip = %s'", netAddr)
		}
	}
	return nil
}

func (s *state) modifyHost(j *job) error {
	var p struct {
		Name  string
		Owner string
	}
	getParams(j, &p)
	host := p.Name
	owner := p.Owner

	// Special handling for ID-host:
	// - remove trailing network name from host name,
	// - limit search to this network definition
	net := ""
	if strings.HasPrefix(host, "id:") {
		// ID host is extended by network name: host:id:a.b@c.d.net_name
		parts := strings.Split(host, ".")
		l := len(parts) - 1
		net = "network:" + parts[l]
		host = strings.Join(parts[:l], ".")
	}
	host = "host:" + host
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if n, ok := toplevel.(*ast.Network); ok {
			if net != "" && n.Name != net {
				return false
			}
			for _, h := range n.Hosts {
				if h.Name == host {
					h.Change("owner", owner)
					return true
				}
			}
		}
		return false
	})
	if !found {
		return fmt.Errorf("Can't find '%s'", host)
	}
	return nil
}

func (s *state) createToplevel(j *job) error {
	var p struct {
		Definition string
		File       string
		OkIfExists bool `json:"ok_if_exists"`
	}
	getParams(j, &p)
	obj, err := parser.ParseToplevel([]byte(p.Definition))
	if err != nil {
		return err
	}
	file := path.Clean(p.File)
	if path.IsAbs(file) {
		return fmt.Errorf("Invalid absolute filename: %s", file)
	}
	// Prevent dangerous filenames, especially starting with "../".
	if file == "" || file[0] == '.' {
		return fmt.Errorf("Invalid filename %s", file)
	}
	// Do nothing if node already exists.
	if p.OkIfExists {
		name := obj.GetName()
		found := false
		s.Modify(func(n ast.Toplevel) bool {
			if name == n.GetName() {
				found = true
			}
			return false
		})
		if found {
			return nil
		}
	}
	obj.Order()
	s.CreateToplevel(file, obj)
	return nil
}

func (s *state) deleteToplevel(j *job) error {
	var p struct {
		Name string
	}
	getParams(j, &p)
	return s.DeleteToplevel(p.Name)
}

func (s *state) deleteOwner(j *job) error {
	var p struct {
		Name string
	}
	getParams(j, &p)
	name := "owner:" + p.Name
	return s.DeleteToplevel(name)
}

func (s *state) deleteService(j *job) error {
	var p struct {
		Name string
	}
	getParams(j, &p)
	name := "service:" + p.Name
	return s.DeleteToplevel(name)
}

type jsonMap map[string]interface{}

func getOwnerPath(name string) string {
	file := "owner"
	if strings.HasPrefix(name, "DA_TOKEN_") {
		file += "-token"
	}
	return file
}

func (s *state) createOwner(j *job) error {
	var p struct {
		Name       string
		Admins     []string
		Watchers   []string
		OkIfExists int `json:"ok_if_exists"`
	}
	getParams(j, &p)
	watchers := ""
	if p.Watchers != nil {
		watchers = fmt.Sprintf("watchers = %s;", strings.Join(p.Watchers, ", "))
	}
	def := fmt.Sprintf("owner:%s = { admins = %s; %s}",
		p.Name, strings.Join(p.Admins, ", "), watchers)
	params, _ := json.Marshal(jsonMap{
		"definition":   def,
		"file":         getOwnerPath(p.Name),
		"ok_if_exists": p.OkIfExists != 0,
	})
	return s.createToplevel(&job{Params: params})
}

func (s *state) modifyOwner(j *job) error {
	var p struct {
		Name     string
		Admins   []string
		Watchers []string
	}
	getParams(j, &p)
	owner := "owner:" + p.Name
	return s.ModifyObj(owner, func(toplevel ast.Toplevel) error {
		n := toplevel.(*ast.TopStruct)
		n.ChangeAttr("admins", p.Admins)
		n.ChangeAttr("watchers", p.Watchers)
		return nil
	})
}

func (s *state) addToGroup(j *job) error {
	var p struct {
		Name   string
		Object string
	}
	getParams(j, &p)
	add, err := parser.ParseUnion([]byte(p.Object))
	if err != nil {
		return err
	}
	group := "group:" + p.Name
	return s.ModifyObj(group, func(toplevel ast.Toplevel) error {
		n := toplevel.(*ast.TopList)
		n.Elements = append(n.Elements, add...)

		// Sort list of objects.
		n.Order()
		return nil
	})
}

func getServicePath(name string) string {
	file := "rule"
	if !fileop.IsDir(file) {
		// Ignore error, is recognized later, when file can't be written.
		os.Mkdir(file, 0777)
	}
	if len(name) > 0 {
		s0 := strings.ToUpper(name[0:1])
		c0 := s0[0]
		if 'A' <= c0 && c0 <= 'Z' || '0' <= c0 && c0 <= '9' {
			return path.Join(file, s0)
		}
	}
	return path.Join(file, "other")
}

type jsonRule struct {
	Action string
	Src    string
	Dst    string
	Prt    string
}

func getParams(j *job, p interface{}) {
	json.Unmarshal(j.Params, p)
}

func getRule(sv *ast.Service, num, count int) (*ast.Rule, error) {
	idx, err := getRuleIdx(sv, num, count)
	if err != nil {
		return nil, err
	}
	return sv.Rules[idx], nil
}

func getRuleIdx(sv *ast.Service, num, count int) (int, error) {
	idx := num - 1
	n := len(sv.Rules)
	if count > 0 && n != count {
		return 0, fmt.Errorf("rule_count %d doesn't match, have %d rules in %s",
			count, n, sv.Name)
	}
	if idx < 0 || idx >= n {
		return 0, fmt.Errorf("Invalid rule_num %d, have %d rules in %s",
			idx+1, n, sv.Name)
	}
	return idx, nil
}

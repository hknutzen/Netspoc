package api

/*
Process jobs of Netspoc-API

COPYRIGHT AND DISCLAIMER
(c) 2021 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
)

type state struct {
	*astset.State
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR JOB ...\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
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

	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, netspocPath)

	s := new(state)
	var err error
	s.State, err = astset.Read(netspocPath)
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
	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
	}
	s.Print()
	return 0
}

type job struct {
	Method string
	Params json.RawMessage
	Crq    string
}

var handler = map[string]func(*state, *job) error{
	"create_toplevel":  (*state).createToplevel,
	"delete_toplevel":  (*state).deleteToplevel,
	"create_host":      (*state).createHost,
	"modify_host":      (*state).modifyHost,
	"create_owner":     (*state).createOwner,
	"modify_owner":     (*state).modifyOwner,
	"delete_owner":     (*state).deleteOwner,
	"add_to_group":     (*state).addToGroup,
	"create_service":   (*state).createService,
	"delete_service":   (*state).deleteService,
	"add_to_user":      (*state).addToUser,
	"remove_from_user": (*state).removeFromUser,
	"add_to_rule":      (*state).addToRule,
	"remove_from_rule": (*state).removeFromRule,
	"add_rule":         (*state).addRule,
	"delete_rule":      (*state).deleteRule,
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
	s.RemoveServiceFromOverlaps(name)
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
	s0 := strings.ToUpper(name[0:1])
	c0 := s0[0]
	if 'A' <= c0 && c0 <= 'Z' || '0' <= c0 && c0 <= '9' {
		file = path.Join(file, s0)
	} else {
		file = path.Join(file, "other")
	}
	return file
}

type jsonRule struct {
	Action string
	Src    string
	Dst    string
	Prt    string
}

func (s *state) createService(j *job) error {
	var p struct {
		Name        string
		Description string
		User        string
		Rules       []jsonRule
	}
	getParams(j, &p)
	rules := ""
	for _, ru := range p.Rules {
		rules += fmt.Sprintf("%s src=%s; dst=%s; prt=%s; ",
			ru.Action, ru.Src, ru.Dst, ru.Prt)
	}
	descr := ""
	if p.Description != "" {
		descr = "description = " + p.Description + "\n"
	}
	def := fmt.Sprintf("service:%s = { %s user = %s; %s }",
		p.Name, descr, p.User, rules)
	params, _ := json.Marshal(jsonMap{
		"definition": def,
		"file":       getServicePath(p.Name),
	})
	return s.createToplevel(&job{Params: params})
}

func (s *state) addToUser(j *job) error {
	var p struct {
		Service string
		User    string
	}
	getParams(j, &p)
	add, err := parser.ParseUnion([]byte(p.User))
	if err != nil {
		return err
	}
	service := "service:" + p.Service
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		sv.User.Elements = append(sv.User.Elements, add...)
		// Sort list of users.
		sv.Order()
		return nil
	})
}

func (s *state) removeFromUser(j *job) error {
	var p struct {
		Service string
		User    string
	}
	getParams(j, &p)
	service := "service:" + p.Service
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		return delUnion(sv.User, service, -1, p.User)
	})
}

func (s *state) addToRule(j *job) error {
	var p struct {
		Service string
		RuleNum int `json:"rule_num"`
		Src     string
		Dst     string
		Prt     string
	}
	getParams(j, &p)
	parse := func(elements string) (add []ast.Element, err error) {
		if elements != "" {
			add, err = parser.ParseUnion([]byte(elements))
		}
		return
	}
	srcEl, err := parse(p.Src)
	if err != nil {
		return err
	}
	dstEl, err := parse(p.Dst)
	if err != nil {
		return err
	}
	service := "service:" + p.Service
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		rule, err := getRule(sv, p.RuleNum)
		if err != nil {
			return err
		}
		rule.Src.Elements = append(rule.Src.Elements, srcEl...)
		rule.Dst.Elements = append(rule.Dst.Elements, dstEl...)
		if p.Prt != "" {
			attr := rule.Prt
			for _, prt := range strings.Split(p.Prt, ",") {
				prt = strings.TrimSpace(prt)
				attr.ValueList = append(attr.ValueList, &ast.Value{Value: prt})
			}
		}
		sv.Order()
		return nil
	})
}

func (s *state) removeFromRule(j *job) error {
	var p struct {
		Service string
		RuleNum int `json:"rule_num"`
		Src     string
		Dst     string
		Prt     string
	}
	getParams(j, &p)
	service := "service:" + p.Service
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		rule, err := getRule(sv, p.RuleNum)
		if err != nil {
			return err
		}
		if err := delUnion(rule.Src, service, p.RuleNum, p.Src); err != nil {
			return err
		}
		if err := delUnion(rule.Dst, service, p.RuleNum, p.Dst); err != nil {
			return err
		}
		if p.Prt != "" {
			attr := rule.Prt
		PRT:
			for _, prt := range strings.Split(p.Prt, ",") {
				p1 := strings.ReplaceAll(prt, " ", "")
				l := attr.ValueList
				for i, v := range l {
					p2 := strings.ReplaceAll(v.Value, " ", "")
					if p1 == p2 {
						attr.ValueList = append(l[:i], l[i+1:]...)
						continue PRT
					}
				}
				return fmt.Errorf("Can't find '%s' in rule %d of %s",
					prt, p.RuleNum, service)
			}
		}
		sv.Order()
		return nil
	})
}

func (s *state) addRule(j *job) error {
	var p struct {
		Service string
		jsonRule
	}
	getParams(j, &p)
	service := "service:" + p.Service
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		return addSvRule(sv, &p.jsonRule)
	})
}

func (s *state) deleteRule(j *job) error {
	var p struct {
		Service string
		RuleNum int `json:"rule_num"`
	}
	getParams(j, &p)
	service := "service:" + p.Service
	var err error
	return s.ModifyObj(service, func(toplevel ast.Toplevel) error {
		sv := toplevel.(*ast.Service)
		var idx int
		idx, err = getRuleIdx(sv, p.RuleNum)
		if err == nil {
			sv.Rules = append(sv.Rules[:idx], sv.Rules[idx+1:]...)
		}
		return err
	})
}

func addSvRule(sv *ast.Service, p *jsonRule) error {
	rule := new(ast.Rule)
	switch p.Action {
	case "deny":
		rule.Deny = true
	case "permit":
	default:
		return fmt.Errorf("Expected 'permit' or 'deny': '%s'", p.Action)
	}
	getUnion := func(name string, elements string) (*ast.NamedUnion, error) {
		union, err := parser.ParseUnion([]byte(elements))
		return &ast.NamedUnion{Name: name, Elements: union}, err
	}
	var err error
	rule.Src, err = getUnion("src", p.Src)
	if err != nil {
		return err
	}
	rule.Dst, err = getUnion("dst", p.Dst)
	if err != nil {
		return err
	}
	var prtList []*ast.Value
	for _, prt := range strings.Split(p.Prt, ",") {
		prt = strings.TrimSpace(prt)
		prtList = append(prtList, &ast.Value{Value: prt})
	}
	rule.Prt = &ast.Attribute{Name: "prt", ValueList: prtList}
	l := sv.Rules
	if rule.Deny {
		// Append in front after existing deny rules.
		for i, r := range l {
			if !r.Deny {
				sv.Rules = make([]*ast.Rule, 0, len(l)+1)
				sv.Rules = append(sv.Rules, l[:i]...)
				sv.Rules = append(sv.Rules, rule)
				sv.Rules = append(sv.Rules, l[i:]...)
				break
			}
		}
	} else {
		sv.Rules = append(l, rule)
	}
	return nil
}

func delUnion(
	where *ast.NamedUnion, sv string, rNum int, elements string) error {

	if elements == "" {
		return nil
	}
	del, err := parser.ParseUnion([]byte(elements))
	if err != nil {
		return err
	}
OBJ:
	for _, obj1 := range del {
		p1 := printer.Element(obj1)
		l := where.Elements
		for i, obj2 := range l {
			p2 := printer.Element(obj2)
			if p1 == p2 {
				where.Elements = append(l[:i], l[i+1:]...)
				continue OBJ
			}
		}
		num := ""
		if rNum > -1 {
			num = fmt.Sprintf(" of rule %d", rNum)
		}
		return fmt.Errorf("Can't find '%s' in '%s'%s of %s",
			p1, where.Name, num, sv)
	}
	return nil
}

func getParams(j *job, p interface{}) {
	json.Unmarshal(j.Params, p)
}

func getRule(sv *ast.Service, num int) (*ast.Rule, error) {
	idx, err := getRuleIdx(sv, num)
	if err != nil {
		return nil, err
	}
	return sv.Rules[idx], nil
}

func getRuleIdx(sv *ast.Service, num int) (int, error) {
	idx := num - 1
	n := len(sv.Rules)
	if idx < 0 || idx >= n {
		return 0, fmt.Errorf("Invalid rule_num %d, have %d rules in %s",
			idx+1, n, sv.Name)
	}
	return idx, nil
}

func showErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

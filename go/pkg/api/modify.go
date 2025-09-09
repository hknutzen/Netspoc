package api

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
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
			"Usage: %s [options] FILE|DIR JOB \n%s",
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
	if len(args) != 2 {
		fs.Usage()
		return 1
	}
	netspocPath := args[0]
	jobPath := args[1]

	showErr := func(format string, args ...any) {
		fmt.Fprintf(d.Stderr, "Error: "+format+"\n", args...)
	}

	s := new(state)
	var err error
	s.State, err = astset.Read(netspocPath)
	if err != nil {
		// Text of this error message is checked in git-worker1 of Netspoc-API.
		showErr("While reading netspoc files: %s", err)
		return 1
	}
	if err := s.doJobFile(jobPath); err != nil {
		showErr("%s", err)
		return 1
	}
	s.ShowChanged(d.Stderr, *quiet)
	s.Print()
	return 0
}

type job struct {
	Method string
	Params json.RawMessage
	Crq    string
}

var handler = map[string]func(*state, *job) error{
	"add":         (*state).patch,
	"delete":      (*state).patch,
	"set":         (*state).patch,
	"create_host": (*state).createHost,
}

func (s *state) doJobFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	return s.doJob(data)
}

func (s *state) doJob(data json.RawMessage) error {
	j := new(job)
	if err := json.Unmarshal(data, j); err != nil {
		return fmt.Errorf("In JSON input: %s", err)
	}
	// Check once if j.Params is given and has expected JSON type.
	if len(j.Params) == 0 {
		return fmt.Errorf("Missing \"params\" in JSON input")
	}
	var dummy map[string]any
	if err := json.Unmarshal(j.Params, &dummy); err != nil {
		return fmt.Errorf("In \"params\" of JSON input: %s", err)
	}
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
		Jobs []json.RawMessage
	}
	getParams(j, &p)
	for _, raw := range p.Jobs {
		if err := s.doJob(raw); err != nil {
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
	if left, _, found := strings.Cut(ip, "-"); found {
		attr = "range"
		ip1 = left
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

func getParams(j *job, p any) {
	// Ignore error and handle params with wrong type like missing params.
	json.Unmarshal(j.Params, p)
}

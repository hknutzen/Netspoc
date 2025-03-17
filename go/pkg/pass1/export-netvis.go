package pass1

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
	"io"
)

func ExportNetvisMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	// Argument processing
	args := fs.Args()
	if len(args) <= 0 || len(args) > 1 {
		fs.Usage()
		return 1
	}
	path := args[0]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
	}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.exportNetvis(d.Stdout, path)
	})
}

type visBase struct {
	Id        string        `json:"id"`
	Type      string        `json:"type"`
	InArea    string        `json:"in_area,omitempty"`
	Address   string        `json:"address,omitempty"`
	Neighbors []visNeighbor `json:"neighbors"`
}

type visNeighbor struct {
	Id            string `json:"id"`
	NeighborCount int    `json:"neighbor_count"`
	IsTunnel      bool   `json:"is_tunnel,omitempty"`
}
type visNetwork struct {
	visBase
	Hosts []string `json:"hosts"`
}

type visRouter = visBase

func (c *spoc) exportNetvis(stdout io.Writer, path string) {
	c.readNetspoc(path)
	c.setZone()
	networks := make(map[string]visNetwork)
	routers := make(map[string]visRouter)

	for _, n := range c.symTable.network {
		getVisNetwork(n, networks)
	}
	for _, r := range c.symTable.router {
		getVisRouter(r, routers)
	}
	data := struct {
		Network map[string]visNetwork `json:"network"`
		Router  map[string]visRouter  `json:"router"`
	}{
		networks, routers,
	}
	out, _ := json.Marshal(data)
	fmt.Fprintln(stdout, string(out))

}

func getVisNetwork(net *network, networks map[string]visNetwork) {
	var node visNetwork
	node.Id = net.name
	node.Type = "network"
	if net.ipType != unnumberedIP {
		node.Address = net.ipp.String()
	}

	if a := net.zone.inArea; a != nil {
		node.InArea = a.name
	}

	getVisNeigh := func(intf *routerIntf) visNeighbor {
		r := intf.router
		if r.origRouter != nil {
			r = r.origRouter
		}
		return visNeighbor{Id: r.name, NeighborCount: len(r.interfaces)}
	}

	for _, in := range net.interfaces {
		node.Neighbors = append(node.Neighbors, getVisNeigh(in))
	}
	for _, h := range net.hosts {
		node.Hosts = append(node.Hosts, h.name)
	}
	networks[net.name] = node
}

func getVisRouter(r *router, routers map[string]visRouter) {
	var node visRouter
	node.Id = r.name

	intfs := r.origIntfs
	if intfs == nil {
		intfs = r.interfaces
	}
	routerArea := intfs[0].network.zone.inArea

	var typ = "router"
	if r.managed == "" {
		if r.routingOnly {
			typ += ": routing_only"
		}
	} else {
		typ += ": " + r.managed
	}

	node.Type = typ

	seen := make(map[*area]bool)
	for _, intf := range intfs {
		if intf.network.ipType == tunnelIP {
			for _, intf2 := range intf.network.interfaces {
				if intf2.router != r {
					node.Neighbors = append(node.Neighbors,
						visNeighbor{Id: intf2.router.name, NeighborCount: len(intf2.router.interfaces), IsTunnel: true})
				}
			}
		} else {
			node.Neighbors = append(node.Neighbors,
				visNeighbor{Id: intf.network.name, NeighborCount: len(intf.network.interfaces)})
			a := intf.network.zone.inArea
			if a != routerArea {
				routerArea = nil
			}
			if a != nil && !seen[a] && r.managed != "" {
				node.Neighbors = append(node.Neighbors,
					visNeighbor{Id: a.name, NeighborCount: len(a.border) + len(a.inclusiveBorder)})
				seen[a] = true
			}
		}
	}
	if routerArea != nil {
		node.InArea = routerArea.name
	}
	routers[r.name] = node
}

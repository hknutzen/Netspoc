package pass1

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
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
	if len(args) != 1 {
		fs.Usage()
		return 1
	}
	path := args[0]

	cnf := conf.ConfigFromFile(path)
	cnf.Quiet = *quiet

	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.exportNetvis(d.Stdout, path)
	})
}

type visBase struct {
	Id        string        `json:"id"`
	Type      string        `json:"type"`
	InArea    string        `json:"in_area,omitempty"`
	Address   string        `json:"address,omitempty"`
	Address2  string        `json:"address2,omitempty"`
	Neighbors []visNeighbor `json:"neighbors"`
}

type visNeighbor struct {
	Id            string `json:"id"`
	NeighborCount int    `json:"neighbor_count"`
	IsTunnel      bool   `json:"is_tunnel,omitzero"`
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
	json.MarshalWrite(stdout, data,
		json.Deterministic(true),
		json.FormatNilSliceAsNull(true),
	)
	fmt.Fprintln(stdout)

}

func getVisNetwork(net *network, networks map[string]visNetwork) {
	var node visNetwork
	node.Id = net.name
	node.Type = "network"
	if net.ipType != unnumberedIP {
		node.Address = net.ipp.String()
		if net2 := net.combined46; net2 != nil {
			node.Address2 = net2.ipp.String()
		}
	}

	if a := net.zone.inArea; a != nil {
		node.InArea = a.name
	}

	addNeighbors := func(net *network, ignoreCombined bool) {
		for _, intf := range net.interfaces {
			if !(ignoreCombined && intf.isCombined46()) {
				r := intf.router
				if r.origRouter != nil {
					r = r.origRouter
				}
				node.Neighbors = append(node.Neighbors, visNeighbor{Id: r.name, NeighborCount: routerNeighborCount(r)})
			}
		}
	}

	addNeighbors(net, false)

	if net.isCombined46() {
		addNeighbors(net.combined46, true)
	}

	for _, h := range net.hosts {
		node.Hosts = append(node.Hosts, h.name)
	}
	networks[net.name] = node
}

func routerNeighborCount(r *router) int {
	seen := make(map[string]bool)
	add := func(r *router) {
		for _, intf := range r.interfaces {
			seen[intf.network.name] = true
		}
	}
	add(r)
	if r.isCombined46() {
		add(r.combined46)
	}
	return len(seen)
}

func getVisRouter(r *router, routers map[string]visRouter) {
	var node visRouter
	node.Id = r.name

	var intfs intfList
	getIntfs := func(r *router) intfList {
		intfs = r.origIntfs
		if intfs == nil {
			intfs = r.interfaces
		}
		return intfs
	}
	intfs = getIntfs(r)

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

	seen := make(map[string]bool)

	networkNeighborCount := func(net *network) int {
		seen := make(map[string]bool)
		add := func(net *network) {
			for _, intf := range net.interfaces {
				seen[intf.router.name] = true
			}
		}
		add(net)
		if net.isCombined46() {
			add(net.combined46)
		}
		return len(seen)
	}

	addNeighbors := func(r *router, ignoreCombined bool) {
		for _, intf := range getIntf(r) {
			if !(ignoreCombined && intf.isCombined46()) {
				if intf.network.ipType == tunnelIP {
					for _, intf2 := range intf.network.interfaces {
						if intf2.router != r {
							node.Neighbors = append(node.Neighbors,
								visNeighbor{Id: intf2.router.name, NeighborCount: routerNeighborCount(intf2.router), IsTunnel: true})
						}
					}
				} else {
					node.Neighbors = append(node.Neighbors,
						visNeighbor{Id: intf.network.name, NeighborCount: networkNeighborCount(intf.network)})
					a := intf.network.zone.inArea
					if a != routerArea {
						routerArea = nil
					}
					if a != nil && !seen[a.name] && r.managed != "" {
						node.Neighbors = append(node.Neighbors,
							visNeighbor{Id: a.name, NeighborCount: len(a.border) + len(a.inclusiveBorder)})
						seen[a.name] = true
					}
				}
			}
		}
	}

	addNeighbors(r, false)

	if r.isCombined46() {
		addNeighbors(r.combined46, true)
	}

	if routerArea != nil {
		node.InArea = routerArea.name
	}
	routers[r.name] = node
}

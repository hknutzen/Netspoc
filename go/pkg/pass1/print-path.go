package pass1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
)

func PrintPathMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR SOURCE DESTINATION\n%s",
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
	if len(args) != 3 {
		fs.Usage()
		return 1
	}
	path := args[0]
	params := args[1:]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
	}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.printPath(d.Stdout, path, params)
	})
}

func (c *spoc) printPath(stdout io.Writer, path string, params []string) {
	c.readNetspoc(path)
	c.setZone()
	c.setPath()

	var l [2]*network
	for i, obj := range params {
		parsed, err := parser.ParseUnion([]byte(obj))
		if err != nil {
			c.abort("%v", err)
		}
		elements := c.expandGroup(parsed, "print-path", false)
		c.stopOnErr()
		if len(elements) != 1 {
			if !(len(elements) == 2 && elements[0].isCombined46()) {
				c.abort("Only one element allowed in %s", elements)
			}
		}
		switch el := elements[0].(type) {
		case *network:
			l[i] = el
		case *host:
			l[i] = el.network
		case *routerIntf:
			l[i] = el.network
		default:
			c.abort("Unsupported element: %v", elements[0])
		}
	}

	znl := make(map[*zone]netList)
	isUsed := make(map[string]bool)
	isUsed[l[0].name] = true
	isUsed[l[1].name] = true
	znl[l[0].zone] = append(znl[l[0].zone], l[0])
	znl[l[1].zone] = append(znl[l[1].zone], l[1])
	c.singlePathWalk(l[0], l[1], func(r *groupedRule, i, o *routerIntf) {
		isUsed[i.router.name] = true
		isUsed[i.network.name] = true
		isUsed[o.network.name] = true
		znl[i.zone] = append(znl[i.zone], i.network)
		znl[o.zone] = append(znl[o.zone], o.network)
	}, "Router")
	c.stopOnErr()

	var markPathInZone func(netList)
	markPathInZone = func(list netList) {
		if len(list) <= 1 {
			return
		}
		markUnconnectedPair(list[0], list[1], isUsed)
		markPathInZone(list[1:])
	}
	for _, list := range znl {
		markPathInZone(list)
	}

	var used []string
	for e := range isUsed {
		if !strings.HasPrefix(e, "interface") {
			used = append(used, e)
		}
	}
	slices.Sort(used)
	used = slices.Compact(used)
	out, _ := json.Marshal(used)
	fmt.Fprintln(stdout, string(out))
}

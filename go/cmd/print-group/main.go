package main

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/spf13/pflag"
	"os"
)

func main() {
	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR 'group:name,...'\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't print progress messages")
	ipv6 := pflag.BoolP("ipv6", "6", false, "Expect IPv6 definitions")

	nat := pflag.String("nat", "",
		"Use network:name as reference when resolving IP address")
	unused := pflag.BoolP("unused", "u", false,
		"Show only elements not used in any rules")
	name := pflag.BoolP("name", "n", false, "Show only name of elements")
	ip := pflag.BoolP("ip", "i", false, "Show only IP address of elements")
	owner := pflag.BoolP("owner", "o", false, "Show owner of elements")
	admins := pflag.BoolP("admins", "a", false,
		"Show admins of elements as comma separated list")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) != 2 {
		pflag.Usage()
		os.Exit(1)
	}
	path := args[0]
	group := args[1]
	dummyArgs := []string{
		fmt.Sprintf("--verbose=%v", !*quiet),
		fmt.Sprintf("--ipv6=%v", *ipv6),
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	pass1.PrintGroup(path, group, *nat, *ip, *name, *owner, *admins, *unused)
}

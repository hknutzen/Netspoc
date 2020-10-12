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
			"Usage: %s [options] FILE|DIR [service:name ...]\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't print progress messages")
	ipv6 := pflag.BoolP("ipv6", "6", false, "Expect IPv6 definitions")
	keepOwner := pflag.BoolP("owner", "o", false, "Keep referenced owners")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		os.Exit(1)
	}
	path := args[0]
	services := args[1:]

	dummyArgs := []string{
		fmt.Sprintf("--verbose=%v", !*quiet),
		fmt.Sprintf("--ipv6=%v", *ipv6),
		"--max_errors=9999",
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)
	pass1.CutNetspoc(path, services, *keepOwner)
}

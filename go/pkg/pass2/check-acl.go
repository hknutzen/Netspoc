package pass2

import (
	"fmt"
	"golang.org/x/exp/slices"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
)

type packet struct {
	src string
	dst string
	prt string
}

func CheckACLMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [-f file] code/router ACL-NAME ['ip1 ip2 tcp|udp port']...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	fromFile := fs.StringP("file", "f", "", "Read packet descriptions from file")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	// Initialize packet descriptions.
	var packets []*packet
	if *fromFile != "" {
		var err error
		packets, err = readPackets(d.Stderr, *fromFile)
		if err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}

	// Argument processing
	args := fs.Args()
	if !(*fromFile != "" && len(args) >= 2 || len(args) >= 3) {
		fs.Usage()
		return 1
	}
	path := args[0]
	if !strings.HasSuffix(path, ".rules") {
		path += ".rules"
	}
	if !fileop.IsRegular(path) {
		fmt.Fprintf(d.Stderr, "Error: Can't find file %s\n", path)
		return 1
	}

	acl := args[1]

	packets = append(packets, parsePackets(d.Stderr, args[2:])...)

	// Check, which packets match ACL.
	return checkACL(d, path, acl, packets)
}

func readPackets(stderr io.Writer, path string) ([]*packet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Can't %s", err)
	}
	lines := strings.Split(string(data), "\n")
	return parsePackets(stderr, lines), nil
}

func parsePackets(stderr io.Writer, lines []string) []*packet {
	var result []*packet
	warn := func(format string, args ...interface{}) {
		fmt.Fprintf(stderr, "Warning: "+format+"\n", args...)
	}
	checkIP := func(s string) string {
		ip := net.ParseIP(s)
		if ip == nil {
			warn("Ignored packet with invalid IP address: %s", s)
			return ""
		}
		return ip.String()
	}
	checkNum := func(s string, max int) string {
		num, err := strconv.Atoi(s)
		if err != nil || num < 0 || num >= max {
			warn("Ignored packet with invalid protocol number: %s", s)
			return ""
		}
		return strconv.Itoa(num)
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.ToLower(line)
		fields := strings.Fields(line)
		if len(fields) != 4 {
			warn("Ignored packet, must have exactly 4 words: %s", line)
			continue
		}
		ip1 := fields[0]
		ip2 := fields[1]
		prt := fields[2]
		ext := fields[3]
		ip1 = checkIP(ip1)
		ip2 = checkIP(ip2)
		if ip1 == "" || ip2 == "" {
			continue
		}
		switch prt {
		case "tcp", "udp":
			ext = checkNum(ext, 65536)
		case "icmp":
			typ, code, found := strings.Cut(ext, "/")
			if found {
				typ = checkNum(typ, 256)
				code = checkNum(code, 256)
				if typ == "" || code == "" {
					continue
				}
				ext = typ + "/" + code
			} else {
				warn("Ignored icmp packet with invalid type/code: %s", line)
				continue
			}
		case "proto":
			ext = checkNum(ext, 256)
		default:
			warn("Ignored packet with unexpected protocol: %s", line)
			continue
		}
		if ext == "" {
			continue
		}
		p := packet{src: ip1, dst: ip2, prt: prt + " " + ext}
		result = append(result, &p)
	}
	return result
}

// Print each packet to STDOUT.
// Packet, that matches ACL is prefixed with "permit".
// Other packet is prefixed with "deny  ".
func checkACL(d oslink.Data,
	path, acl string, packets []*packet) int {

	rData := readJSON(path)
	var aInfo *aclInfo
	for _, a := range rData.acls {
		if a.name == acl {
			aInfo = a
			break
		}
	}
	if aInfo == nil {
		fmt.Fprintf(d.Stderr, "Error: Unknown ACL: %s\n", acl)
		return 1
	}
	// Remember number of original rules.
	sz := len(aInfo.rules)
	// Add packets as rules.
	addPackets(aInfo, packets)
	// Set relation between original and added rules.
	setupPrtRelation(aInfo.prt2obj)
	setupIPNetRelation(aInfo.ipNet2obj)
	// Remember added original rules because aInfo gets changed
	// during optimization.
	orig := slices.Clone(aInfo.rules[sz:])
	// Optimize rules; marks duplicate and redundant rules as '.deleted'.
	optimizeRules(aInfo)
	// Check added rules.
	for _, p := range orig {
		var action string
		if p.deleted {
			// Packet was redundant to original rule and hence can pass.
			action = "permit"
		} else {
			action = "deny  "
		}
		ip1 := p.src.Addr().String()
		ip2 := p.dst.Addr().String()
		prt := p.prt.name
		fmt.Fprintf(d.Stdout, "%s %s %s %s\n", action, ip1, ip2, prt)
	}
	return 0
}

func addPackets(a *aclInfo, l []*packet) {
	rules := a.rules
	ipNet2obj := a.ipNet2obj
	prt2obj := a.prt2obj
	seen := make(map[packet]bool)
	for _, p := range l {
		// Ignore duplicate packets, because duplicates are redundant to
		// each other and would therefore show inconsistent results.
		if seen[*p] {
			continue
		}
		seen[*p] = true
		ipObj := func(s string) *ipNet {
			if i := strings.Index(s, ":"); i != -1 {
				s += "/128"
			} else {
				s += "/32"
			}
			return getIPNet(s, ipNet2obj)
		}
		src := ipObj(p.src)
		dst := ipObj(p.dst)
		prt := getPrtObj(p.prt, prt2obj)
		rules.push(&ciscoRule{src: src, dst: dst, prt: prt})
	}
	a.rules = rules
}

package pass2

/*
Pass 2 of Netspoc - A Network Security Policy Compiler

(C) 2024 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
)

func panicf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

type ipNet struct {
	netip.Prefix
	optNetworks             *ipNet
	noOptAddrs, needProtect bool
	name                    string
	up                      *ipNet
	isSupernetOfNeedProtect map[*ipNet]bool
}

type name2ipNet map[string]*ipNet

func createIPObj(ipNetName string) *ipNet {
	net := netip.MustParsePrefix(ipNetName)
	return &ipNet{Prefix: net, name: ipNetName}
}

func getIPObj(ip netip.Addr, prefix int, ipNet2obj name2ipNet) *ipNet {
	net, _ := ip.Prefix(prefix)
	name := net.String()
	obj, ok := ipNet2obj[name]
	if !ok {
		obj = &ipNet{Prefix: net, name: name}
		ipNet2obj[name] = obj
	}
	return obj
}

func getIPNet(name string, ipNet2obj name2ipNet) *ipNet {
	obj, ok := ipNet2obj[name]
	if !ok {
		obj = createIPObj(name)
		ipNet2obj[name] = obj
	}
	return obj
}

func ipNetList(names []string, ipNet2obj name2ipNet) []*ipNet {
	result := make([]*ipNet, len(names))
	for i, name := range names {
		result[i] = getIPNet(name, ipNet2obj)
	}
	return result
}

func getNet00(ipv6 bool, ipNet2obj name2ipNet) *ipNet {
	var name string
	if ipv6 {
		name = "::/0"
	} else {
		name = "0.0.0.0/0"
	}
	return getIPNet(name, ipNet2obj)
}

func setupIPNetRelation(ipNet2obj name2ipNet) {
	prefixIPMap := make(map[int]map[netip.Addr]*ipNet)

	// Collect networks into prefixIPMap.
	for _, n := range ipNet2obj {
		ip, prefix := n.Addr(), n.Bits()
		ipMap, ok := prefixIPMap[prefix]
		if !ok {
			ipMap = make(map[netip.Addr]*ipNet)
			prefixIPMap[prefix] = ipMap
		}
		ipMap[ip] = n
	}

	// Compare networks.
	// Go from small to larger networks.
	prefixList := slices.SortedFunc(maps.Keys(prefixIPMap),
		func(a, b int) int { return cmp.Compare(b, a) })
	for i, prefix := range prefixList {
		upperPrefixes := prefixList[i+1:]

		// No supernets available
		if len(upperPrefixes) == 0 {
			break
		}

		ipMap := prefixIPMap[prefix]
		for ip, subnet := range ipMap {

			// Find networks which include current subnet.
			// upperPrefixes holds prefixes of potential supernets.
			for _, p := range upperPrefixes {
				n, _ := ip.Prefix(p)
				if bignet, ok := prefixIPMap[p][n.Addr()]; ok {
					subnet.up = bignet
					break
				}
			}
		}
	}

	// Propagate content of attribute optNetworks to all subnets.
	// Go from large to smaller networks.
	slices.Reverse(prefixList)
	for _, prefix := range prefixList {
		for _, n := range prefixIPMap[prefix] {
			if up := n.up; up != nil {
				if optNetworks := up.optNetworks; optNetworks != nil {
					n.optNetworks = optNetworks
				}
			}
		}
	}
}

func markSupernetsOfNeedProtect(needProtect []*ipNet) {
	for _, intf := range needProtect {
		up := intf.up
		for up != nil {
			if up.isSupernetOfNeedProtect == nil {
				up.isSupernetOfNeedProtect = make(map[*ipNet]bool)
			}
			up.isSupernetOfNeedProtect[intf] = true
			up = up.up
		}
	}
}

type aclInfo struct {
	name                                             string
	isStdACL                                         bool
	isCryptoACL                                      bool
	addPermit                                        bool
	addDeny                                          bool
	filterAnySrc                                     bool
	intfRuHasLog                                     bool
	rulesHasLog                                      bool
	intfRules, rules                                 ciscoRules
	lrules                                           linuxRules
	prt2obj                                          name2Proto
	ipNet2obj                                        name2ipNet
	filterOnly, optNetworks, noOptAddrs, needProtect []*ipNet
	network00                                        *ipNet
	prtIP                                            *proto
	objectGroups                                     []*objGroup
	tier                                             string
	vrf                                              string
	logDeny                                          string
}

func convertACLs(
	jACL *jcode.ACLInfo, jData *jcode.RouterData, ipv6 bool) *aclInfo {

	// Process networks and protocols of each interface individually,
	// because relation between networks may be changed by NAT.
	ipNet2obj := make(name2ipNet)
	prt2obj := make(name2Proto)

	intfRules, hasLog1 := convertRuleObjects(
		jACL.IntfRules, ipNet2obj, prt2obj)
	rules, hasLog2 := convertRuleObjects(
		jACL.Rules, ipNet2obj, prt2obj)

	filterOnly := ipNetList(jACL.FilterOnly, ipNet2obj)

	optNetworks := ipNetList(jACL.OptNetworks, ipNet2obj)
	for _, obj := range optNetworks {
		obj.optNetworks = obj
	}
	noOptAddrs := ipNetList(jACL.NoOptAddrs, ipNet2obj)
	for _, obj := range noOptAddrs {
		obj.noOptAddrs = true
	}
	needProtect := ipNetList(jACL.NeedProtect, ipNet2obj)
	for _, obj := range needProtect {
		obj.needProtect = true
	}

	return &aclInfo{
		name:         jACL.Name,
		isStdACL:     jACL.IsStdACL,
		isCryptoACL:  jACL.IsCryptoACL,
		addPermit:    jACL.AddPermit,
		addDeny:      jACL.AddDeny,
		tier:         jACL.Tier,
		vrf:          jACL.VRF,
		logDeny:      jACL.LogDeny,
		intfRules:    intfRules,
		intfRuHasLog: hasLog1,
		rules:        rules,
		rulesHasLog:  hasLog2,
		prt2obj:      prt2obj,
		ipNet2obj:    ipNet2obj,
		filterOnly:   filterOnly,
		optNetworks:  optNetworks,
		noOptAddrs:   noOptAddrs,
		filterAnySrc: jACL.FilterAnySrc,
		needProtect:  needProtect,
		network00:    getNet00(ipv6, ipNet2obj),
	}
}

func convertRuleObjects(
	rules []*jcode.Rule, ipNet2obj name2ipNet,
	prt2obj name2Proto) (ciscoRules, bool) {

	var expanded ciscoRules
	var hasLog bool
	for _, rule := range rules {
		srcList := ipNetList(rule.Src, ipNet2obj)
		dstList := ipNetList(rule.Dst, ipNet2obj)
		prtList := prtList(rule.Prt, prt2obj)
		var srcRange *proto
		if rule.SrcRange != "" {
			srcRange = getPrtObj(rule.SrcRange, prt2obj)
		}
		hasLog = hasLog || rule.Log != ""
		for _, src := range srcList {
			for _, dst := range dstList {
				for _, prt := range prtList {
					expanded.push(
						&ciscoRule{
							deny:         rule.Deny,
							src:          src,
							dst:          dst,
							srcRange:     srcRange,
							prt:          prt,
							log:          rule.Log,
							optSecondary: rule.OptSecondary,
						})
				}
			}
		}
	}
	return expanded, hasLog
}

type routerData struct {
	model           string
	ipv6            bool
	acls            []*aclInfo
	filterOnlyGroup map[string]*ipNet
	doObjectgroup   bool
	objGroupsMap    map[groupKey][]*objGroup
	objGroupCounter int
	chainCounter    int
	chains          []*lChain
}

func readJSON(path string) *routerData {
	jData := new(jcode.RouterData)
	fd, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	dec := json.NewDecoder(fd)
	if err := dec.Decode(&jData); err != nil {
		panic(err)
	}
	rData := new(routerData)
	if strings.Contains(path, "/ipv6/") {
		rData.ipv6 = true
	}
	rData.model = jData.Model
	rData.doObjectgroup = jData.DoObjectgroup
	acls := make([]*aclInfo, len(jData.ACLs))
	for i, jACL := range jData.ACLs {
		aclInfo := convertACLs(jACL, jData, rData.ipv6)
		acls[i] = aclInfo
		if rData.model == "Linux" {
			addTCPUDPIcmp(aclInfo.prt2obj)
		}
	}
	rData.acls = acls
	return rData
}

func prepareACLs(rData *routerData) {
	for _, aclInfo := range rData.acls {
		prt2obj := aclInfo.prt2obj
		setupPrtRelation(prt2obj)
		aclInfo.prtIP = prt2obj["ip"]
		setupIPNetRelation(aclInfo.ipNet2obj)
		markSupernetsOfNeedProtect(aclInfo.needProtect)
	}
}

func printACL(fd *os.File, aclInfo *aclInfo, routerData *routerData) {
	model := routerData.model
	if model == "Linux" {

		// Print all sub-chains at once before first toplevel chain is printed.
		printChains(fd, routerData)
		printIptablesACL(fd, aclInfo, routerData)
	} else {
		printObjectGroups(fd, aclInfo, model)
		printCiscoACL(fd, aclInfo, routerData)
	}
}

const aclMarker = "#insert "

func printCombinedOther(fd *os.File, config []string, routerData *routerData) {
	aclLookup := make(map[string]*aclInfo)
	prepareACLs(routerData)
	for _, acl := range routerData.acls {
		if routerData.model == "Linux" {
			findChains(acl, routerData)
		} else {
			optimizeRules(acl)
			finalizeCiscoACL(acl, routerData)
		}
		aclLookup[acl.name] = acl
	}

	// Print config and insert printed ACLs at aclMarker.
	for _, line := range config {
		if strings.HasPrefix(line, aclMarker) {
			// Print ACL.
			name := line[len(aclMarker):]
			aclInfo := aclLookup[name]
			printACL(fd, aclInfo, routerData)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}
}

func readFileLines(filename string) []string {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return strings.Split(string(data), "\n")
}

func printRouter(file string) {
	routerData := readJSON(file + ".rules")
	config := readFileLines(file + ".config")
	fd, err := os.Create(file)
	if err != nil {
		panicf("Can't %v", err)
	}
	defer fd.Close()
	switch routerData.model {
	case "PAN-OS":
		printCombinedPanOS(fd, config, routerData)
	case "NSX":
		printCombinedNSX(fd, config, routerData)
	default:
		printCombinedOther(fd, config, routerData)
	}
}

// Try to use pass2 file from previous run.
// If identical files with extension .config and .rules
// exist in directory .prev/, then use copy.
func tryPrev(devicePath, dir, prev string) bool {
	if !fileop.IsDir(prev) {
		return false
	}
	prevFile := prev + "/" + devicePath
	if !fileop.IsRegular(prevFile) {
		return false
	}
	codeFile := dir + "/" + devicePath
	for _, ext := range [...]string{"config", "rules"} {
		pass1name := codeFile + "." + ext
		pass1prev := prevFile + "." + ext
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil {
			return false
		}
	}
	// Try to remove old code file if it was left over somehow.
	os.Remove(codeFile)
	if err := os.Link(prevFile, codeFile); err != nil {
		panic(err)
	}

	// File was found and hardlink was created successfully.
	return true
}

func File(devicePath, dir, prev string) bool {
	if tryPrev(devicePath, dir, prev) {
		return true
	}
	file := dir + "/" + devicePath
	printRouter(file)
	return false
}

package pass2

/*
Pass 2 of Netspoc - A Network Security Policy Compiler

(C) 2021 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

func panicf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

type ipNet struct {
	*net.IPNet
	optNetworks             *ipNet
	noOptAddrs, needProtect bool
	name                    string
	up                      *ipNet
	isSupernetOfNeedProtect map[*ipNet]bool
}

type name2ipNet map[string]*ipNet

func createIPObj(ipNetName string) *ipNet {
	_, net, e := net.ParseCIDR(ipNetName)
	if e != nil {
		panic(e)
	}
	return &ipNet{IPNet: net, name: ipNetName}
}

func getIPObj(ip net.IP, mask net.IPMask, ipNet2obj name2ipNet) *ipNet {
	prefix, _ := mask.Size()
	name := ip.String() + "/" + strconv.Itoa(prefix)
	obj, ok := ipNet2obj[name]
	if !ok {
		obj = &ipNet{IPNet: &net.IPNet{IP: ip, Mask: mask}, name: name}
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
	maskIPMap := make(map[string]map[string]*ipNet)

	// Collect networks into maskIPMap.
	for _, network := range ipNet2obj {
		ip, mask := network.IP, network.Mask
		ipMap, ok := maskIPMap[string(mask)]
		if !ok {
			ipMap = make(map[string]*ipNet)
			maskIPMap[string(mask)] = ipMap
		}
		ipMap[string(ip)] = network
	}

	// Compare networks.
	// Go from smaller to larger networks.
	var maskList []net.IPMask
	for k := range maskIPMap {
		maskList = append(maskList, net.IPMask(k))
	}
	less := func(i, j int) bool {
		return bytes.Compare(maskList[i], maskList[j]) == -1
	}
	sort.Slice(maskList, func(i, j int) bool { return less(j, i) })
	for i, mask := range maskList {
		upperMasks := maskList[i+1:]

		// No supernets available
		if len(upperMasks) == 0 {
			break
		}

		ipMap := maskIPMap[string(mask)]
		for ip, subnet := range ipMap {

			// Find networks which include current subnet.
			// upperMasks holds masks of potential supernets.
			for _, m := range upperMasks {

				i := net.IP(ip).Mask(net.IPMask(m))
				bignet, ok := maskIPMap[string(m)][string(i)]
				if ok {
					subnet.up = bignet
					break
				}
			}
		}
	}

	// Propagate content of attribute optNetworks to all subnets.
	// Go from large to smaller networks.
	sort.Slice(maskList, less)
	for _, mask := range maskList {
		for _, network := range maskIPMap[string(mask)] {
			up := network.up
			if up == nil {
				continue
			}
			if optNetworks := up.optNetworks; optNetworks != nil {
				network.optNetworks = optNetworks
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

	filterOnly := ipNetList(jData.FilterOnly, ipNet2obj)

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
		isStdACL:     jACL.IsStdACL == 1,
		isCryptoACL:  jACL.IsCryptoACL == 1,
		addPermit:    jACL.AddPermit == 1,
		addDeny:      jACL.AddDeny == 1,
		intfRules:    intfRules,
		intfRuHasLog: hasLog1,
		rules:        rules,
		rulesHasLog:  hasLog2,
		prt2obj:      prt2obj,
		ipNet2obj:    ipNet2obj,
		filterOnly:   filterOnly,
		optNetworks:  optNetworks,
		noOptAddrs:   noOptAddrs,
		filterAnySrc: jACL.FilterAnySrc == 1,
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
							deny:         rule.Deny == 1,
							src:          src,
							dst:          dst,
							srcRange:     srcRange,
							prt:          prt,
							log:          rule.Log,
							optSecondary: rule.OptSecondary == 1,
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
	logDeny         string
	filterOnlyGroup *ipNet
	doObjectgroup   bool
	objGroupsMap    map[groupKey][]*objGroup
	objGroupCounter int
	chainCounter    int
	chains          []*lChain
}

func readJSON(path string) *routerData {
	jData := new(jcode.RouterData)
	data, e := ioutil.ReadFile(path)
	if e != nil {
		panic(e)
	}
	e = json.Unmarshal(data, &jData)
	if e != nil {
		panic(e)
	}
	rData := new(routerData)
	if i := strings.Index(path, "/ipv6/"); i != -1 {
		rData.ipv6 = true
	}
	rData.model = jData.Model
	rData.logDeny = jData.LogDeny
	rData.doObjectgroup = jData.DoObjectgroup == 1
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

func prepareACLs(path string) *routerData {
	rData := readJSON(path)
	for _, aclInfo := range rData.acls {
		prt2obj := aclInfo.prt2obj
		setupPrtRelation(prt2obj)
		aclInfo.prtIP = prt2obj["ip"]
		setupIPNetRelation(aclInfo.ipNet2obj)
		markSupernetsOfNeedProtect(aclInfo.needProtect)
		if rData.model == "Linux" {
			findChains(aclInfo, rData)
		} else {
			optimizeRules(aclInfo)
			finalizeCiscoACL(aclInfo, rData)
		}
	}
	return rData
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

func printCombined(config []string, routerData *routerData, outPath string) {
	fd, err := os.Create(outPath)
	if err != nil {
		panicf("Can't open %s for writing: %v", outPath, err)
	}
	aclLookup := make(map[string]*aclInfo)
	for _, acl := range routerData.acls {
		aclLookup[acl.name] = acl
	}

	// Print config and insert printed ACLs at aclMarker.
	for _, line := range config {
		if strings.HasPrefix(line, aclMarker) {
			// Print ACL.
			name := line[len(aclMarker):]
			aclInfo, ok := aclLookup[name]
			if !ok {
				panicf("Unexpected ACL %s", name)
			}
			printACL(fd, aclInfo, routerData)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}

	if err := fd.Close(); err != nil {
		panic(err)
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
		if !fileop.IsRegular(pass1prev) {
			return false
		}
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil {
			return false
		}
	}
	if err := os.Link(prevFile, codeFile); err != nil {
		return false
	}

	// File was found and hardlink was created successfully.
	diag.Msg("Reused .prev/" + devicePath)
	return true
}

func readFileLines(filename string) []string {
	fd, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	result := make([]string, 0)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return result
}

type pass2Result int

const (
	ok pass2Result = iota
	reuse
)

func pass2File(devicePath, dir, prev string, c chan pass2Result) {
	if tryPrev(devicePath, dir, prev) {
		c <- reuse
		return
	}
	file := dir + "/" + devicePath
	routerData := prepareACLs(file + ".rules")
	config := readFileLines(file + ".config")
	printCombined(config, routerData, file)
	c <- ok
}

func applyConcurrent(
	devices chan string, finished chan bool, dir, prev string) {

	var started, generated, reused int
	concurrent := conf.Conf.ConcurrencyPass2
	c := make(chan pass2Result, concurrent)
	workersLeft := concurrent

	waitAndCheck := func() {
		switch <-c {
		case ok:
			generated++
		case reuse:
			reused++
		}
		started--
	}

	// Read to be processed files line by line.
	for devicePath := range devices {
		if 1 >= concurrent {
			// Process sequentially.
			pass2File(devicePath, dir, prev, c)
			waitAndCheck()
		} else if workersLeft > 0 {
			// Start concurrent jobs at beginning.
			go pass2File(devicePath, dir, prev, c)
			workersLeft--
			started++
		} else {
			// Start next job, after some job has finished.
			waitAndCheck()
			go pass2File(devicePath, dir, prev, c)
			started++
		}
	}

	// Wait for all jobs to be finished.
	for started > 0 {
		waitAndCheck()
	}

	if generated > 0 {
		info.Msg("Generated files for %d devices", generated)
	}
	if reused > 0 {
		info.Msg("Reused %d files from previous run", reused)
	}
	finished <- true
}

func Compile(dir string, fromPass1 chan string, finished chan bool) {
	prev := path.Join(dir, ".prev")
	applyConcurrent(fromPass1, finished, dir, prev)

	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	err := os.RemoveAll(prev)
	if err != nil {
		panic(err)
	}
}

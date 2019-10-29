package pass1

import (
	"bytes"
	"encoding/binary"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"strings"
)

//###################################################################
// Convert hosts to subnets.
// Mark subnet relation of subnets.
//###################################################################

// Convert an IP range to a set of covering net.IPNet.
func splitIpRange(lo, hi net.IP, context string) []net.IPNet {
	var l, h uint64
	if len(lo) == 4 && len(hi) == 4 {
		l = uint64(binary.BigEndian.Uint32(lo))
		h = uint64(binary.BigEndian.Uint32(hi))
	} else {
		lo, hi = lo.To16(), hi.To16()
		if bytes.Compare(lo[:8], hi[:8]) != 0 {
			errMsg("IP range of %s is too large. It must fit into /64 network.",
				context)
		}
		l, h = binary.BigEndian.Uint64(lo[8:]), binary.BigEndian.Uint64(hi[8:])
	}
	var result []net.IPNet
	add := func(i, m uint64) {
		var ip net.IP
		var mask net.IPMask
		if len(lo) == net.IPv4len {
			ip = make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, uint32(i))
			mask = make(net.IPMask, net.IPv4len)
			binary.BigEndian.PutUint32(mask, uint32(m))
		} else {
			ip = make(net.IP, net.IPv6len)
			copy(ip, lo)
			binary.BigEndian.PutUint64(ip[8:], i)
			mask = net.CIDRMask(64, 128)
			binary.BigEndian.PutUint64(mask[8:], m)
		}
		result = append(result, net.IPNet{IP: ip, Mask: mask})
	}

IP:
	for l <= h {
		// 255.255.255.255, 127.255.255.255, ..., 0.0.0.3, 0.0.0.1, 0.0.0.0
		var invMask uint64 = 0xffffffffffffffff
		for {
			if l&invMask == 0 {
				end := l | invMask
				if end <= h {
					add(l, ^invMask)
					l = end + 1
					continue IP
				}
			}
			if invMask == 0 {
				break
			}
			invMask >>= 1
		}
	}
	return result
}

func ipNATEqual(n1, n2 map[string]net.IP) bool {
	if len(n1) != len(n2) {
		return false
	}
	for tag, ip1 := range n1 {
		ip2, ok := n2[tag]
		if !ok {
			return false
		}
		if !ip1.Equal(ip2) {
			return false
		}
	}
	return true
}

func checkHostCompatibility(obj, other *netObj) {
	if !ipNATEqual(obj.nat, other.nat) {
		errMsg("Inconsistent NAT definition for %s and %s",
			other.name, obj.name)
	}
	if obj.owner != other.owner {
		warnMsg("Inconsistent owner definition for %s and %s",
			other.name, obj.name)
	}
}

func convertHosts() {
	diag.Progress("Converting hosts to subnets")
	for _, n := range allNetworks {
		if n.unnumbered || n.tunnel {
			continue
		}
		ipv6 := n.ipV6
		var bitstrLen int
		if ipv6 {
			bitstrLen = 128
		} else {
			bitstrLen = 32
		}
		subnetAref := make([]map[string]*subnet, bitstrLen)

		// Converts hosts and ranges to subnets.
		// Eliminate duplicate subnets.
		for _, host := range n.hosts {
			var nets []net.IPNet
			name := host.name
			id := host.id
			if ip := host.ip; ip != nil {
				nets = []net.IPNet{{ip, getHostMask(ip, ipv6)}}
				if id != "" {
					switch strings.Index(id, "@") {
					case 0:
						errMsg("ID of %s must not start with character '@'", name)
					case -1:
						errMsg("ID of %s must contain character '@'", name)
					}
				}
			} else {
				// Convert range.
				nets = splitIpRange(host.ipRange[0], host.ipRange[1], host.name)
				if id != "" {
					if len(nets) > 1 {
						errMsg("Range of %s with ID must expand to exactly one subnet",
							name)
					} else if isHostMask(nets[0].Mask) {
						errMsg("%s with ID must not have single IP", name)
					} else if strings.Index(id, "@") > 0 {
						errMsg("ID of %s must start with character '@'"+
							" or have no '@' at all", name)
					}
				}
			}

			for _, net := range nets {
				size, _ := net.Mask.Size()
				subnetSize := bitstrLen - size
				str2subnet := subnetAref[subnetSize]
				if str2subnet == nil {
					str2subnet = make(map[string]*subnet)
					subnetAref[subnetSize] = str2subnet
				}

				if other := str2subnet[string(net.IP)]; other != nil {
					checkHostCompatibility(&host.netObj, &other.netObj)
					host.subnets = append(host.subnets, other)
				} else {
					s := new(subnet)
					s.name = name
					s.network = n
					s.ip = net.IP
					s.mask = net.Mask
					s.nat = host.nat
					s.owner = host.owner
					s.id = id
					s.ldapId = host.ldapId
					s.radiusAttributes = host.radiusAttributes

					str2subnet[string(net.IP)] = s
					host.subnets = append(host.subnets, s)
					n.subnets = append(n.subnets, s)
				}
			}
		}

		// Set {up} relation and
		// check compatibility of hosts in subnet relation.
		for i := 0; i < len(subnetAref); i++ {
			ip2subnet := subnetAref[i]
			if ip2subnet == nil {
				continue
			}

			for ipStr, subnet := range ip2subnet {
				ip := net.IP(ipStr)
				// Search for enclosing subnet.
				for j := i + 1; j < len(subnetAref); j++ {
					mask := net.CIDRMask(bitstrLen-j, bitstrLen)
					ip = ip.Mask(mask)
					if up := subnetAref[j][string(ip)]; up != nil {
						subnet.up = up
						checkHostCompatibility(&subnet.netObj, &up.netObj)
						break
					}
				}

				// Use network, if no enclosing subnet found.
				if subnet.up == nil {
					subnet.up = n
				}
			}
		}

		// Attribute .up has been set for all subnets now.
		// Do the same for unmanaged interfaces.
		for _, intf := range n.interfaces {
			r := intf.router
			if r.managed == "" && !r.routingOnly {
				intf.up = n
			}
		}
	}
}

//#######################################################################
// Convert hosts in normalized serviceRules to subnets or to networks.
//#######################################################################

func applySrcDstModifier(group []srvObj) []srvObj {
	var modified []srvObj
	var unmodified []srvObj
	seen := make(map[*network]bool)
	for _, obj := range group {
		var n *network
		switch x := obj.(type) {
		case *host:
			if x.id != "" {
				unmodified = append(unmodified, obj)
				continue
			}
			n = x.network
		case *routerIntf:
			if x.router.managed != "" || x.loopback {
				unmodified = append(unmodified, obj)
				continue
			}
			n = x.network
		case *network:
			unmodified = append(unmodified, obj)
			continue
		}
		if !seen[n] {
			seen[n] = true
			modified = append(modified, n)
		}
	}
	return append(unmodified, modified...)
}

var subnetWarningSeen = make(map[*subnet]bool)

func ConvertHostsInRules() (ruleList, ruleList) {
	convertHosts()
	process := func(rules []*serviceRule) ruleList {
		cRules := make(ruleList, 0, len(rules))
		for _, rule := range rules {
			processList := func(list []srvObj, context string) []someObj {
				var cList []someObj
				subnet2host := make(map[*subnet]*host)
				for _, obj := range list {
					switch x := obj.(type) {
					case *network:
						cList = append(cList, x)
					case *routerIntf:
						cList = append(cList, x)
					case *host:
						for _, s := range x.subnets {

							// Handle special case, where network and subnet
							// have identical address.
							// E.g. range = 10.1.1.0-10.1.1.255.
							// Convert subnet to network, because
							// - different objects with identical IP
							//   can't be checked for redundancy properly.
							n := s.network
							if bytes.Compare(s.mask, n.mask) == 0 {
								if !n.hasIdHosts && !subnetWarningSeen[s] {
									subnetWarningSeen[s] = true
									warnMsg(
										"Use %s instead of %s\n"+
											" because both have identical address",
										n.name, s.name)
								}
								cList = append(cList, n)
							} else if other := subnet2host[s]; other != nil {
								warnMsg("%s and %s overlap in %s of %s",
									x.name, other.name, context, rule.rule.service.name)
							} else {
								subnet2host[s] = x
								cList = append(cList, s)
							}
						}
					}
				}
				return cList
			}
			if rule.srcNet {
				rule.src = applySrcDstModifier(rule.src)
			}
			if rule.dstNet {
				rule.dst = applySrcDstModifier(rule.dst)
			}
			converted := new(groupedRule)
			converted.serviceRule = rule
			converted.src = processList(rule.src, "src")
			converted.dst = processList(rule.dst, "dst")
			cRules.push(converted)
		}
		return cRules
	}
	return process(sRules.permit), process(sRules.deny)
}

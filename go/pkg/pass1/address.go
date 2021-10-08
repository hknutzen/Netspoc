package pass1

import (
	"inet.af/netaddr"
	"net"
)

// Take higher bits from network NAT, lower bits from original IP.
// This works with and without NAT.
func mergeIP(ip netaddr.IP, nat *network) netaddr.IP {
	bytes := ip.IPAddr().IP
	n := nat.ipp.IPNet()
	l := len(n.IP)
	merged := make(net.IP, l)
	for i := 0; i < l; i++ {
		merged[i] = n.IP[i] | bytes[i] & ^n.Mask[i]
	}
	result, _ := netaddr.FromStdIPNet(&net.IPNet{IP: merged, Mask: n.Mask})
	return result.IP()
}

func getHostPrefix(ipv6 bool) uint8 {
	if ipv6 {
		return 128
	}
	return 32
}

var zeroIP, _ = netaddr.ParseIP("0.0.0.0")
var zeroIPv6, _ = netaddr.ParseIP("::")

func getZeroIp(ipv6 bool) netaddr.IP {
	if ipv6 {
		return zeroIPv6
	} else {
		return zeroIP
	}
}

var network00 = &network{
	ipObj:          ipObj{name: "network:0/0"},
	ipp:            netaddr.IPPrefixFrom(getZeroIp(false), 0),
	isAggregate:    true,
	hasOtherSubnet: true,
}

var network00v6 = &network{
	ipObj:          ipObj{name: "network:0/0"},
	ipp:            netaddr.IPPrefixFrom(getZeroIp(true), 0),
	isAggregate:    true,
	hasOtherSubnet: true,
}

func getNetwork00(ipv6 bool) *network {
	if ipv6 {
		return network00v6
	} else {
		return network00
	}
}

func getNatNetwork(n *network, m natMap) *network {
	if nat := m[n]; nat != nil {
		return nat
	}
	return n
}

func (obj *network) address(m natMap) netaddr.IPPrefix {
	n := getNatNetwork(obj, m)
	return n.ipp
}

func (obj *subnet) address(m natMap) netaddr.IPPrefix {
	n := getNatNetwork(obj.network, m)
	return natAddress(obj.ipp.IP(), obj.ipp.Bits(), obj.nat, n, obj.network.ipV6)
}

func (obj *routerIntf) address(m natMap) netaddr.IPPrefix {
	n := getNatNetwork(obj.network, m)
	if obj.ipType == negotiatedIP {
		return n.ipp
	}
	ipV6 := obj.network.ipV6
	return natAddress(obj.ip, getHostPrefix(ipV6), obj.nat, n, ipV6)
}

func natAddress(ip netaddr.IP, bits uint8, nat map[string]netaddr.IP,
	n *network, ipV6 bool) netaddr.IPPrefix {

	if n.dynamic {
		natTag := n.natTag
		if ip, ok := nat[natTag]; ok {

			// Single static NAT IP for this interface.
			return netaddr.IPPrefixFrom(ip, getHostPrefix(ipV6))
		} else {
			return n.ipp
		}
	}
	return netaddr.IPPrefixFrom(mergeIP(ip, n), bits)
}

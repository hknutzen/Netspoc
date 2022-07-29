package pass1

import (
	"net/netip"
)

// Take higher bits from network NAT, lower bits from original IP.
// This works with and without NAT.
func mergeIP(ip netip.Addr, nat *network) netip.Addr {
	bytes := ip.AsSlice()
	mask := make([]byte, len(bytes))
	for i := range mask {
		mask[i] = 0xff
	}
	m, _ := netip.AddrFromSlice(mask)
	p, _ := m.Prefix(nat.ipp.Bits())
	mask = p.Addr().AsSlice()
	n := nat.ipp.Addr().AsSlice()
	merged := make([]byte, len(bytes))
	for i, m := range mask {
		merged[i] = n[i] | bytes[i] & ^m
	}
	result, _ := netip.AddrFromSlice(merged)
	return result
}

func getHostPrefix(ipv6 bool) int {
	if ipv6 {
		return 128
	}
	return 32
}

var zeroIP, _ = netip.ParseAddr("0.0.0.0")
var zeroIPv6, _ = netip.ParseAddr("::")

func getZeroIp(ipv6 bool) netip.Addr {
	if ipv6 {
		return zeroIPv6
	} else {
		return zeroIP
	}
}

func (c *spoc) getNetwork00(ipv6 bool) *network {
	if ipv6 {
		return c.network00v6
	} else {
		return c.network00
	}
}

func getNatNetwork(n *network, m natMap) *network {
	if nat := m[n]; nat != nil {
		return nat
	}
	return n
}

func (obj *network) address(m natMap) netip.Prefix {
	n := getNatNetwork(obj, m)
	return n.ipp
}

func (obj *subnet) address(m natMap) netip.Prefix {
	n := getNatNetwork(obj.network, m)
	return natAddress(obj.ipp.Addr(), obj.ipp.Bits(), obj.nat, n, obj.network.ipV6)
}

func (obj *routerIntf) address(m natMap) netip.Prefix {
	n := getNatNetwork(obj.network, m)
	if obj.ipType == negotiatedIP {
		return n.ipp
	}
	ipV6 := obj.network.ipV6
	return natAddress(obj.ip, getHostPrefix(ipV6), obj.nat, n, ipV6)
}

func natAddress(ip netip.Addr, bits int, nat map[string]netip.Addr,
	n *network, ipV6 bool) netip.Prefix {

	if n.dynamic {
		natTag := n.natTag
		if ip, ok := nat[natTag]; ok {

			// Single static NAT IP for this interface.
			return netip.PrefixFrom(ip, getHostPrefix(ipV6))
		} else {
			return n.ipp
		}
	}
	return netip.PrefixFrom(mergeIP(ip, n), bits)
}

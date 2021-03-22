package pass1

import (
	"net"
)

// Take higher bits from network NAT, lower bits from original IP.
// This works with and without NAT.
func mergeIP(ip net.IP, nat *network) net.IP {
	l := len(nat.ip)
	merged := make(net.IP, l)
	for i := 0; i < l; i++ {
		merged[i] = nat.ip[i] | ip[i] & ^nat.mask[i]
	}
	return merged
}

func getBroadcastIP(nat *network) net.IP {
	l := len(nat.ip)
	broadcast := make(net.IP, l)
	for i := 0; i < l; i++ {
		broadcast[i] = nat.ip[i] | ^nat.mask[i]
	}
	return broadcast
}

func getHostMask(ipv6 bool) net.IPMask {
	if ipv6 {
		return net.CIDRMask(128, 128)
	}
	return net.CIDRMask(32, 32)
}

var zeroIP = net.ParseIP("0.0.0.0").To4()
var zeroIPv6 = net.ParseIP("::")

func getZeroIp(ipv6 bool) net.IP {
	if ipv6 {
		return zeroIPv6
	} else {
		return zeroIP
	}
}

func getZeroMask(ipv6 bool) net.IPMask {
	if ipv6 {
		return net.CIDRMask(0, 128)
	}
	return net.CIDRMask(0, 32)
}

var network00 = &network{
	ipObj: ipObj{
		name: "network:0/0",
		ip:   getZeroIp(false),
	},
	mask:           getZeroMask(false),
	isAggregate:    true,
	hasOtherSubnet: true,
}

var network00v6 = &network{
	ipObj: ipObj{
		name: "network:0/0",
		ip:   getZeroIp(true),
	},
	mask:           getZeroMask(true),
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

func (obj *network) address(m natMap) *net.IPNet {
	n := getNatNetwork(obj, m)
	return &net.IPNet{IP: n.ip, Mask: n.mask}
}

func (obj *subnet) address(m natMap) *net.IPNet {
	n := getNatNetwork(obj.network, m)
	return natAddress(obj.ip, obj.mask, obj.nat, n, obj.network.ipV6)
}

func (obj *routerIntf) address(m natMap) *net.IPNet {
	n := getNatNetwork(obj.network, m)
	if obj.ipType == negotiatedIP {
		return &net.IPNet{IP: n.ip, Mask: n.mask}
	}
	ipV6 := obj.network.ipV6
	return natAddress(obj.ip, getHostMask(ipV6), obj.nat, n, ipV6)
}

func natAddress(ip net.IP, mask net.IPMask, nat map[string]net.IP,
	n *network, ipV6 bool) *net.IPNet {

	if n.dynamic {
		natTag := n.natTag
		if ip, ok := nat[natTag]; ok {

			// Single static NAT IP for this interface.
			return &net.IPNet{IP: ip, Mask: getHostMask(ipV6)}
		} else {
			return &net.IPNet{IP: n.ip, Mask: n.mask}
		}
	}
	return &net.IPNet{IP: mergeIP(ip, n), Mask: mask}
}

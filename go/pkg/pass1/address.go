package pass1

import (
	"net"
)

func getHostMask(ip net.IP, ipv6 bool) net.IPMask {
	if ipv6 {
		return net.CIDRMask(128, 128)
	}
	return net.CIDRMask(32, 32)
}

var zeroIP = net.ParseIP("0.0.0.0")
var zeroIPv6 = net.ParseIP("::")

func getZeroIp(ipv6 bool) net.IP {
	if ipv6 {
		return zeroIPv6
	} else {
		return zeroIP
	}
}

func getNatNetwork(network *network, natSet natSet) *network {
	for tag, natNet := range network.nat {
		if (*natSet)[tag] {
			return natNet
		}
	}
	return network
}

func (obj *network) address(nn natSet) net.IPNet {
	network := getNatNetwork(obj, nn)
	return net.IPNet{IP: network.ip, Mask: network.mask}
}

func (obj *subnet) address(nn natSet) net.IPNet {
	network := getNatNetwork(obj.network, nn)
	return natAddress(obj.ip, obj.mask, obj.nat, network, obj.network.ipV6)
}

func (obj *routerIntf) address(nn natSet) net.IPNet {
	network := getNatNetwork(obj.network, nn)
	if obj.negotiated {
		return net.IPNet{IP: network.ip, Mask: network.mask}
	}
	ipV6 := obj.network.ipV6
	return natAddress(obj.ip, getHostMask(obj.ip, ipV6), obj.nat, network, ipV6)
}

func natAddress(ip net.IP, mask net.IPMask, nat map[string]net.IP, network *network, ipV6 bool) net.IPNet {
	if network.dynamic {
		natTag := network.natTag
		if ip, ok := nat[natTag]; ok {

			// Single static NAT IP for this interface.
			return net.IPNet{IP: ip, Mask: getHostMask(ip, ipV6)}
		} else {
			return net.IPNet{IP: network.ip, Mask: network.mask}
		}
	}

	// Take higher bits from network NAT, lower bits from original IP.
	// This works with and without NAT.
	n := len(network.ip)
	natIP := make(net.IP, n)
	for i := 0; i < n; i++ {
		natIP[i] = network.ip[i] | ip[i] & ^network.mask[i]
	}
	return net.IPNet{IP: natIP, Mask: mask}
}

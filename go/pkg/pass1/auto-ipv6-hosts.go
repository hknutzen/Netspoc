package pass1

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"go4.org/netipx"
)

const (
	hostsUnset = iota
	hostsNone
	hostsReadable
	hostsBinary
)

func (c *spoc) getAutoIPv6Hosts(a *ast.Attribute, ctx string) string {
	v := c.getSingleValue(a, ctx)
	switch v {
	default:
		c.err("Expected 'readable|binary|none' in '%s' of %s", a.Name, ctx)
	case "readable", "binary", "none":
	}
	return v
}

func (c *spoc) addAutoIPv6Hosts() {
	for _, n := range c.allNetworks {
		attr := n.autoIPv6Hosts
		if !n.ipV6 {
			if n.combined46 == nil && attr != "" {
				c.warn("Ignoring 'auto_ipv6_hosts' at IPv4 only %s", n)
			}
			continue
		}
		if attr == "" || attr == "none" {
			continue
		}
		n4 := n.combined46
		if n4 == nil {
			c.warn("Ignoring 'auto_ipv6_hosts' at IPv6 only %s", n)
			continue
		}
		ipp := n.ipp
		if ipp.Bits() > 64 {
			c.err("Can't use 'auto_ipv6_hosts' at %s having prefix len > 64", n)
			continue
		}
		for _, h4 := range n4.hosts {
			if h4.combined46 == nil {
				attr2 := attr
				if at := h4.autoIPv6Hosts; at != "" {
					if at == "none" {
						continue
					}
					attr2 = at
				}
				cp := *h4
				cp.ipV6 = true
				cp.combined46 = h4
				h4.combined46 = &cp
				if h4.ip.IsValid() {
					cp.ip = genIPv6FromIPv4(h4.ip, ipp, attr2)
				} else if h4.ipRange.IsValid() {
					from := genIPv6FromIPv4(h4.ipRange.From(), ipp, attr2)
					to := genIPv6FromIPv4(h4.ipRange.To(), ipp, attr2)
					cp.ipRange = netipx.IPRangeFrom(from, to)
				}
				cp.nat = nil
				n.hosts = append(n.hosts, &cp)
			}
		}
	}
}

func genIPv6FromIPv4(ip netip.Addr, ipp netip.Prefix, attr string) netip.Addr {
	b16 := ipp.Addr().AsSlice()
	switch attr {
	case "binary":
		b4 := ip.AsSlice()
		copy(b16[12:], b4)
	case "readable":
		s4 := ip.String()
		dec := strings.Split(s4, ".")
		s := fmt.Sprintf("%04s%04s%04s%04s", dec[0], dec[1], dec[2], dec[3])
		for i := 0; i < 8; i++ {
			x := s[2*i : 2*i+2]
			fmt.Sscanf(x, "%x", &b16[8+i])
		}
	}
	result, _ := netip.AddrFromSlice(b16)
	return result
}

package pass1

import (
	"net/netip"
)

// lastIP returns the last IP in the prefix.
func lastIP(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}
	a16 := p.Addr().As16()
	var off int
	var bits int = 128
	if p.Addr().Is4() {
		off = 12
		bits = 32
	}
	for b := p.Bits(); b < bits; b++ {
		byteNum, bitInByte := b/8, 7-(b%8)
		a16[off+byteNum] |= 1 << uint(bitInByte)
	}
	if p.Addr().Is4() {
		return netip.AddrFrom16(a16).Unmap()
	} else {
		return netip.AddrFrom16(a16)
	}
}

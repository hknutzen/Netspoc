package pass2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type proto struct {
	protocol    string
	ports       [2]int
	established bool
	icmpType    int
	icmpCode    int
	name        string
	up          *proto
	hasNeighbor bool
}
type name2Proto map[string]*proto

func createPrtObj(descr string) *proto {
	var protocol string
	detail := ""
	if i := strings.Index(descr, " "); i == -1 {
		protocol = descr
	} else {
		protocol = descr[:i]
		detail = descr[i+1:]
	}
	prt := proto{name: descr, protocol: protocol}
	switch protocol {
	case "tcp", "udp":
		// tcp, tcp 80, tcp 80-90, tcp established
		var p1, p2 int
		i := strings.Index(detail, "-")
		if i == -1 {
			switch detail {
			case "established":
				prt.established = true
				fallthrough
			case "":
				p1, p2 = 1, 65535
			default:
				p1, _ = strconv.Atoi(detail)
				p2 = p1
			}
		} else {
			p1, _ = strconv.Atoi(detail[:i])
			p2, _ = strconv.Atoi(detail[i+1:])
		}
		prt.ports = [2]int{p1, p2}
	case "icmp":
		// icmp, icmp 3, icmp 3/13
		if detail == "" {
			prt.icmpType = -1
		} else {
			if i := strings.Index(detail, "/"); i == -1 {
				prt.icmpType, _ = strconv.Atoi(detail)
				prt.icmpCode = -1
			} else {
				prt.icmpType, _ = strconv.Atoi(detail[:i])
				prt.icmpCode, _ = strconv.Atoi(detail[i+1:])
			}
		}
	case "proto":
		prt.protocol = detail
	}
	return &prt
}

func getPrtObj(name string, prt2obj name2Proto) *proto {
	obj, ok := prt2obj[name]
	if !ok {
		obj = createPrtObj(name)
		prt2obj[name] = obj
	}
	return obj
}

func prtList(names []string, prt2obj name2Proto) []*proto {
	result := make([]*proto, len(names))
	for i, name := range names {
		result[i] = getPrtObj(name, prt2obj)
	}
	return result
}

// Set {up} relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Set attribute {hasNeighbor} to range adjacent to upper port.
// Abort on overlapping ranges.
func orderRanges(protocol string, prt2obj name2Proto, up *proto) {
	var ranges []*proto
	for _, v := range prt2obj {
		if v.protocol == protocol && !v.established {
			ranges = append(ranges, v)
		}
	}

	// Sort by low port. If low ports are equal, sort reverse by high port.
	// I.e. larger ranges coming first, if there are multiple ranges
	// with identical low port.
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].ports[0] < ranges[j].ports[0] ||
			ranges[i].ports[0] == ranges[j].ports[0] &&
				ranges[i].ports[1] > ranges[j].ports[1]
	})

	// Check current range a.ports[0,1] for sub-ranges, starting at position $i.
	// Set attributes {up} and {hasNeighbor}.
	// Return position of range which isn't sub-range or 0
	// if end of array is reached.
	var checkSubrange func(a *proto, i int) int
	checkSubrange = func(a *proto, i int) int {
		for {
			if i == len(ranges) {
				return 0
			}
			b := ranges[i]

			// Neighbors
			// aaaabbbb
			if a.ports[1]+1 == b.ports[0] {

				// Mark protocol as candidate for joining of port ranges during
				// optimization.
				a.hasNeighbor = true
				b.hasNeighbor = true

				// Mark other ranges having identical start port.
				for _, c := range ranges[i+1:] {
					if c.ports[0] != b.ports[0] {
						break
					}
					c.hasNeighbor = true
				}
			}

			// Not related.
			// aaaa    bbbbb
			if a.ports[1] < b.ports[0] {
				return i
			}

			// a includes b.
			// aaaaaaa
			//  bbbbb
			if a.ports[1] >= b.ports[1] {
				b.up = a
				i = checkSubrange(b, i+1)

				// Stop at end of array.
				if i == 0 {
					return 0
				}
				continue
			}

			// a and b are overlapping.
			// aaaaa
			//   bbbbbb
			panicf("Unexpected overlapping ranges [%d-%d] [%d-%d]",
				a.ports[0], a.ports[1], b.ports[0], b.ports[1])
		}
	}

	if len(ranges) == 0 {
		return
	}
	index := 0
	for {
		a := ranges[index]
		a.up = up
		index = checkSubrange(a, index+1)
		if index == 0 {
			return
		}
	}
}

func setupPrtRelation(prt2obj name2Proto) {
	prtIP := getPrtObj("ip", prt2obj)
	icmpUp, ok := prt2obj["icmp"]
	if !ok {
		icmpUp = prtIP
	}

	for _, prt := range prt2obj {
		protocol := prt.protocol
		if protocol == "icmp" {
			if prt.icmpType != -1 {
				if prt.icmpCode != -1 {
					up, ok := prt2obj[fmt.Sprint("icmp ", prt.icmpType)]
					if !ok {
						up = icmpUp
					}
					prt.up = up
				} else {
					prt.up = icmpUp
				}
			} else {
				prt.up = prtIP
			}
		} else if _, err := strconv.Atoi(protocol); err == nil {

			// Numeric protocol.
			prt.up = prtIP
		}
	}

	orderRanges("tcp", prt2obj, prtIP)
	orderRanges("udp", prt2obj, prtIP)

	if tcpEstabl, ok := prt2obj["tcp established"]; ok {
		up, ok := prt2obj["tcp"]
		if !ok {
			up = prtIP
		}
		tcpEstabl.up = up
	}
}

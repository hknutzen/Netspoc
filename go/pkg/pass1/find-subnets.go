package pass1

import (
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"sort"
)

func natName(n *network) string {
	name := n.descr
	if name == "" {
		name = n.name
	}
	return name
}

func processSubnetRelation(maskIPMap map[string]map[string]*network,
	work func(sub, big *network)) {

	maskList := make([]net.IPMask, 0, len(maskIPMap))
	for k, _ := range maskIPMap {
		maskList = append(maskList, net.IPMask(k))
	}

	sort.Slice(maskList, func(i, j int) bool {
		// Go from smaller to larger networks, i.e big mask value first.
		return bytes.Compare(maskList[i], maskList[j]) == 1
	})
	for i, mask := range maskList {
		upperMasks := maskList[i+1:]

		// No supernets available
		if len(upperMasks) == 0 {
			break
		}

		ipMap := maskIPMap[string(mask)]
		ipList := make([]string, 0, len(ipMap))
		for ip, _ := range ipMap {
			ipList = append(ipList, ip)
		}
		sort.Strings(ipList)
		for _, ip := range ipList {
			sub := ipMap[ip]

			// Find networks which include current subnet.
			// upperMasks holds masks of potential supernets.
			for _, m := range upperMasks {
				i := net.IP(ip).Mask(net.IPMask(m))
				if big, ok := maskIPMap[string(m)][string(i)]; ok {
					work(sub, big)

					// Only handle direct subnet relation.
					break
				}
			}
		}
	}
}

// All interfaces and hosts of a network must be located in that part
// of the network which doesn't overlap with some subnet.
func checkSubnets(n, subnet *network, context string) {
	if n.isAggregate || subnet.isAggregate {
		return
	}
	subIp, subMask := subnet.ip, subnet.mask
	check := func(ip1, ip2 net.IP, object netObj) {
		if matchIp(ip1, subIp, subMask) ||
			ip2 != nil &&
				(matchIp(ip2, subIp, subMask) ||
					bytes.Compare(ip1, subIp) != -1 && bytes.Compare(subIp, ip2) != -1) {

			// NAT to an interface address (masquerading) is allowed.
			if tags := object.bindNat; tags != nil {
				if tag2 := subnet.natTag; tag2 != "" {
					for _, tag := range tags {
						if tag == tag2 &&
							object.ip.Equal(subnet.ip) && isHostMask(subnet.mask) {
							return
						}
					}
				}
			}
			if context != "" {
				context = " in " + context
			}
			warnMsg("IP of %s overlaps with subnet %s%s",
				object.name, subnet.name, context)
		}
	}
	for _, intf := range n.interfaces {
		if intf.unnumbered || intf.negotiated || intf.tunnel || intf.short ||
			intf.bridged {
			continue
		}
		check(intf.ip, nil, intf.netObj)
	}
	for _, host := range n.hosts {
		if ip := host.ip; ip != nil {
			check(ip, nil, host.netObj)
		} else {
			r := host.ipRange
			check(r[0], r[1], host.netObj)
		}
	}
}

//###################################################################
// Find sub-networks
// Mark each network with the smallest network enclosing it.
//###################################################################

func findSubnetsInZone0(z *zone) {

	// Check NAT inside zone.
	// Find networks of zone which use a NATed address inside the zone.
	// - Use this NATed address in subnet checks.
	// - If a subnet relation exists, then this NAT must be unique inside
	//   the zone.

	natSet := z.natDomain.natSet

	// Add networks of zone to maskIPMap.
	// Use NAT IP/mask.
	maskIPMap := make(map[string]map[string]*network)
	add := func(n *network) {
		nn := n
		for tag, n2 := range n.nat {
			if (*natSet)[tag] {
				nn = n2
				break
			}
		}
		ip, mask := nn.ip, nn.mask
		ipMap := maskIPMap[string(mask)]
		if ipMap == nil {
			ipMap = make(map[string]*network)
			maskIPMap[string(mask)] = ipMap
		}

		// Found two different networks with identical IP/mask.
		if other := ipMap[string(ip)]; other != nil {
			errMsg("%s and %s have identical IP/mask in %s",
				n.name, other.name, z.name)
		} else {

			// Store original network under NAT IP/mask.
			ipMap[string(ip)] = n
		}
	}
	for _, n := range z.networks {
		add(n)
	}
	for _, n := range z.ipmask2aggregate {
		add(n)
	}

	// Process networks of zone, that are in direct subnet relation.
	processSubnetRelation(maskIPMap, func(sub, big *network) {

		// Collect subnet relation.
		sub.up = big

		//debug("%s -up-> %s", sub, big)
		if sub.isAggregate {
			big.networks = append(big.networks, sub.networks...)
		} else {
			big.networks.push(sub)
		}

		checkSubnets(big, sub, "")
	})

	// For each subnet N find the largest non-aggregate network
	// which encloses N. If one exists, store it in maxUpNet.
	// This is used to exclude subnets from z.networks below.
	// It is also used to derive attribute {maxRoutingNet}.
	maxUpNet := make(map[*network]*network)
	var setMaxNet func(n *network) *network
	setMaxNet = func(n *network) *network {
		if n == nil {
			return nil
		}
		if maxNet := maxUpNet[n]; maxNet != nil {
			return maxNet
		}
		if maxNet := setMaxNet(n.up); maxNet != nil {
			if !n.isAggregate {
				maxUpNet[n] = maxNet

				//debug("%s maxUp %s", n, maxNet);
			}
			return maxNet
		}
		if n.isAggregate {
			return nil
		}
		return n
	}
	for _, n := range z.networks {
		setMaxNet(n)
	}

	// For each subnet N find the largest non-aggregate network
	// inside the same zone which encloses N.
	// If one exists, store it in {maxRoutingNet}. This is used
	// for generating static routes.
	// We later check, that subnet relation remains stable even if
	// NAT is applied.
	for _, n := range z.networks {
		if maxUpNet[n] == nil {
			continue
		}

		// debug "Check %s", n
		var maxRouting *network
		up := n.up
	UP:
		for up != nil {

			// If larger network is hidden at some place, only use
			// it for routing, if original network is hidden there
			// as well.
			// We don't need to check here that subnet relation is
			// maintained for NAT addresses.
			// That is enforced later in findSubnetsInNatDomain.
			for _, upNatInfo := range up.nat {
				if !upNatInfo.hidden {
					continue
				}
				natMap := n.nat
				if natMap == nil {
					break UP
				}
				natTag := upNatInfo.natTag
				natInfo := natMap[natTag]
				if natInfo == nil {
					break UP
				}
				if !natInfo.hidden {
					break UP
				}
			}
			if !up.isAggregate {
				maxRouting = up
			}
			up = up.up
		}
		if maxRouting != nil {
			n.maxRoutingNet = maxRouting
			// debug "Found %s", maxRouting
		}
	}

	// Remove subnets of non-aggregate networks.
	j := 0
	for _, n := range z.networks {
		if maxUpNet[n] == nil {
			z.networks[j] = n
			j++
		}
	}
	z.networks = z.networks[:j]

	// It is valid to have an aggregate in a zone which has no matching
	// networks. This can be useful to add optimization rules at an
	// intermediate device.
}

// Find subnet relation between networks inside a zone.
// - subnet.up = bignet;
func FindSubnetsInZone() {
	diag.Progress("Finding subnets in zone")
	for _, z := range zones {
		findSubnetsInZone0(z)
	}
}

// Dynamic NAT to loopback interface is OK,
// if NAT is applied at device of loopback interface.
func natToLoopbackOk(loopbackNetwork, natNetwork *network) bool {
	natTag1 := natNetwork.natTag
	deviceCount := 0
	allDeviceOk := 0

	// In case of virtual loopback, the loopback network
	// is attached to two or more routers.
	// Loop over these devices.
	for _, loopIntf := range loopbackNetwork.interfaces {
		deviceCount++

		// Check all interfaces of attached device.
	INTF:
		for _, allIntf := range loopIntf.router.interfaces {
			for _, tag := range allIntf.bindNat {
				if tag == natTag1 {
					allDeviceOk++
					break INTF
				}
			}
		}
	}
	return allDeviceOk == deviceCount
}

func findSubnetsInNatDomain0(domains []*natDomain, networks netList) {

	// List of all networks and NAT networks having an IP address.
	// We need this in deterministic order.
	var natNetworks netList

	// Mapping from NAT network to original network.
	origNet := make(map[*network]*network)
	for _, n := range networks {
		natNetworks.push(n)
		origNet[n] = n
		for _, natNetwork := range n.nat {
			if natNetwork.hidden {
				continue
			}
			origNet[natNetwork] = n
			natNetworks.push(natNetwork)
		}
	}

	// 1. step:
	// Compare IP/mask of all networks and NAT networks and find relations
	// isIn and identical.

	// Mapping Mask -> IP -> Network|NAT Network.
	maskIPMap := make(map[string]map[string]*network)

	// Mapping from one network|NAT network to list of elements with
	// identical IP address.
	identical := make(map[*network]netList)

	for _, nn := range natNetworks {
		ip, mask := nn.ip, nn.mask
		ipMap := maskIPMap[string(mask)]
		if ipMap == nil {
			ipMap = make(map[string]*network)
			maskIPMap[string(mask)] = ipMap
		}
		if other := ipMap[string(ip)]; other != nil {

			// Bild lists of identical networks.
			if identical[other] == nil {
				identical[other] = netList{other}
			}
			identical[other] = append(identical[other], nn)
		} else {
			ipMap[string(ip)] = nn
		}
	}

	// Calculate isIn relation from IP addresses;
	// This includes all addresses of all networks in all NAT domains.
	isIn := make(map[*network]*network)
	processSubnetRelation(maskIPMap, func(sub, big *network) {
		isIn[sub] = big
	})

	// 2. step:
	// Analyze isIn and 'identical' relation for different NAT domains.

	// Mapping from subnet to bignet in same zone.
	// Bignet must be marked, if subnet is marked later with hasOtherSubnet.
	pendingOtherSubnet := make(map[*network]netList)
	var markNetworkAndPending func(*network)
	markNetworkAndPending = func(n *network) {
		if n.hasOtherSubnet {
			return
		}
		n.hasOtherSubnet = true
		if list, ok := pendingOtherSubnet[n]; ok {
			delete(pendingOtherSubnet, n)
			for _, e := range list {
				markNetworkAndPending(e)
			}
		}
	}
	subnetInZone := make(map[*network]map[*network]map[*natDomain]bool)
	identSeen := make(netMap)
	type netPair [2]*network
	relationSeen := make(map[netPair]bool)
	for _, domain := range domains {

		// Ignore NAT domain consisting of empty zone from unnumbered networks
		// and surrounded by unmanaged devices.
		// An address conflict would not be observable inside this NAT domain.
		domainZones := domain.zones
		if len(domainZones) == 1 {
			zone := domainZones[0]
			if len(zone.networks) == 0 {
				managedSeen := false
				for _, intf := range zone.interfaces {
					if intf.router.managed != "" {
						managedSeen = true
					}
				}
				if !managedSeen {
					continue
				}
			}
		}

		natSet := domain.natSet

		// Mark networks visible in current NAT domain.
		// - Real network is visible, if none of its NAT tag are active.
		// - NAT network is visible if its NAT tag is active.
		// - It is located in same NAT partition as current NAT domain.
		visible := make(map[*network]bool)
	NETWORK:
		for _, natNetwork := range natNetworks {
			if tag := natNetwork.natTag; tag != "" {
				// NAT network
				if !(*natSet)[tag] {
					continue NETWORK
				}
			} else {
				// Original network having NAT definitions.
				for tag, _ := range natNetwork.nat {
					if (*natSet)[tag] {
						continue NETWORK
					}
				}
			}
			visible[natNetwork] = true
		}

		// Mark and analyze networks having identical IP/mask in
		// current NAT domain.
		hasIdentical := make(map[*network]bool)
		for one, list := range identical {
			var filtered netList
			for _, n := range list {
				if visible[n] {
					filtered.push(n)
					hasIdentical[n] = true
				}
			}
			if len(filtered) == 0 {
				continue
			}

			// If list has been fully analyzed once, don't check it again.
			if identSeen[one] {
				continue
			}
			if len(filtered) == len(list) {
				identSeen[one] = true
			}

			// Compare pairs of networks with identical IP/mask.
			natOther := filtered[0]
			other := origNet[natOther]
			for _, natNetwork := range filtered[1:] {
				n := origNet[natNetwork]
				error := false
				if other.isAggregate || n.isAggregate {

					// Check supernet rules and prevent secondary optimization,
					// if identical IP address occurrs in different zones.
					other.hasOtherSubnet = true
					n.hasOtherSubnet = true
					//debug("identical %s %s", n.name, other.name)
				} else if natOther.dynamic && natNetwork.dynamic {

					// Dynamic NAT of different networks
					// to a single new IP/mask is OK.
				} else if other.loopback && natNetwork.dynamic {
					if !natToLoopbackOk(other, natNetwork) {
						error = true
					}
				} else if natOther.dynamic && n.loopback {
					if !natToLoopbackOk(n, natOther) {
						error = true
					}
				} else if n.bridged && other.bridged {

					// Parts of bridged network have identical IP by design.
				} else {
					error = true
				}
				if error {
					errMsg("%s and %s have identical IP/mask\n"+
						" in %s",
						natName(natNetwork), natName(natOther), domain.name)
				}
			}
		}

		// Check pairs of networks, that are in subnet relation.
	SUBNET:
		for _, natSubnet := range natNetworks {
			natBignet := isIn[natSubnet]
			if natBignet == nil {
				continue
			}

			// If invisible, search other networks with identical IP.
			if !visible[natSubnet] {
				identList := identical[natSubnet]
				foundOther := false
				for _, identNet := range identList {
					if visible[identNet] {
						natSubnet = identNet
						foundOther = true
						break
					}
				}
				if !foundOther {
					continue
				}
			}

			// If invisible, search other networks with identical or larger IP.
		BIGNET:
			for !visible[natBignet] {
				identList := identical[natBignet]
				for _, identNet := range identList {
					if visible[identNet] {
						natBignet = identNet
						break BIGNET
					}
				}
				natBignet = isIn[natBignet]
				if natBignet == nil {
					continue SUBNET
				}
			}
			subnet := origNet[natSubnet]

			// Collect subnet/supernet pairs in same zone for later check.
			{
				var idSubnets netList
				if identList := identical[natSubnet]; identList != nil {
					for _, identNet := range identList {
						if visible[identNet] {
							idSubnets.push(origNet[identNet])
						}
					}
				} else {
					idSubnets = netList{subnet}
				}
				for _, subnet := range idSubnets {
					zone := subnet.zone
					natBignet := natBignet
					for {
						bignet := origNet[natBignet]
						if visible[natBignet] && bignet.zone == zone {
							bigMap := subnetInZone[subnet]
							if bigMap == nil {
								bigMap = make(map[*network]map[*natDomain]bool)
								subnetInZone[subnet] = bigMap
							}
							domMap := bigMap[bignet]
							if domMap == nil {
								domMap = make(map[*natDomain]bool)
								bigMap[bignet] = domMap
							}
							domMap[domain] = true
							break
						}
						natBignet = isIn[natBignet]
						if natBignet == nil {
							break
						}
					}
				}
			}

			//debug("%s <= %s", natName(natSubnet), natName(natBignet))
			if relationSeen[netPair{natBignet, natSubnet}] {
				continue
			}
			relationSeen[netPair{natBignet, natSubnet}] = true
			bignet := origNet[natBignet]

			// Mark network having subnet in same zone, if subnet has
			// subsubnet in other zone.
			// Remember subnet relation in same zone in pendingOtherSubnet,
			// if current status of subnet is not known,
			// since status may change later.
			sameZone := bignet.zone == subnet.zone
			if sameZone {
				if subnet.hasOtherSubnet || hasIdentical[subnet] {
					bignet.hasOtherSubnet = true
				} else {
					pendingOtherSubnet[subnet] =
						append(pendingOtherSubnet[subnet], bignet)
				}
			} else {
				// Mark network having subnet in other zone.
				markNetworkAndPending(bignet)

				// Mark aggregate that has other *supernet*.
				// In this situation, addresses of aggregate
				// are part of supernet and located in another
				// zone.
				if subnet.isAggregate {
					markNetworkAndPending(subnet)
				}
			}

			// No check needed for unexpected subnet relation.
			if subnet.isAggregate {
				continue
			}

			// Use next larger non aggregate network when checking for
			// unexpected subnet relation.
		REALNET:
			for natBignet.isAggregate || !visible[natBignet] {
				identList := identical[natBignet]
				for _, identNet := range identList {
					if visible[identNet] && !identNet.isAggregate {
						natBignet = identNet
						break REALNET
					}
				}
				natBignet = isIn[natBignet]
				if natBignet == nil {
					continue SUBNET
				}
			}
			bignet = origNet[natBignet]
			sameZone = bignet.zone == subnet.zone

			if printType := conf.Conf.CheckSubnets; printType != "" {

				// Take original bignet, because currently
				// there's no method to specify a natted network
				// as value of subnet_of.
				if !(bignet.hasSubnets || natSubnet.subnetOf == bignet ||
					natSubnet.isLayer3) {

					// Prevent multiple error messages in
					// different NAT domains.
					if natSubnet.subnetOf == nil {
						natSubnet.subnetOf = bignet
					}
					warnOrErrMsg(printType,
						"%s is subnet of %s\n"+
							" in %s.\n"+
							" If desired, either declare attribute"+
							" 'subnet_of' or attribute 'has_subnets'",
						natName(natSubnet), natName(natBignet), domain.name)
				}
			}

			if !sameZone {
				checkSubnets(natBignet, natSubnet, domain.name)
			}
		}
	}

	// Check networks in same zone for stable subnet relation over all
	// NAT domains. If networks are in relation at one NAT domain, they
	// must also be in relation in all other domains.
	net2dom2hidden := make(map[*network]map[*natDomain]bool)
	for _, n := range networks {
		var hiddenTags []string
		for tag, nn := range n.nat {
			if nn.hidden {
				hiddenTags = append(hiddenTags, tag)
			}
		}
		if hiddenTags == nil {
			continue
		}
		dom2hidden := make(map[*natDomain]bool)
		for _, domain := range domains {
			natSet := domain.natSet
			for _, tag := range hiddenTags {
				if (*natSet)[tag] {
					dom2hidden[domain] = true
				}
			}
		}
		net2dom2hidden[n] = dom2hidden
	}

	for subnet, net2dom2isSubnet := range subnetInZone {
		subDom2hidden := net2dom2hidden[subnet]
		for bignet, dom2isSubnet := range net2dom2isSubnet {
			bigDom2hidden := net2dom2hidden[bignet]

			// Subnet is subnet of bignet in at least one NAT domain.
			// Check that in each NAT domain
			// - subnet relation holds or
			// - at least one of both networks is hidden.
		DOMAIN:
			for _, domain := range domains {

				// Ok, is subnet in current NAT domain.
				if dom2isSubnet[domain] {
					continue
				}

				// If one or both networks are hidden, this does
				// not count as changed subnet relation.
				if bigDom2hidden[domain] {
					continue
				}
				if subDom2hidden[domain] {
					continue
				}

				// Ignore relation, if both are aggregates,
				// because IP addresses of aggregates can't be changed by NAT.
				if subnet.isAggregate && bignet.isAggregate {
					continue
				}

				// Also check transient subnet relation.
				up := subnet
				for {
					up2 := up.up
					if up2 == nil {
						break
					}
					if !subnetInZone[up][up2][domain] {
						break
					}
					if up2 == bignet {
						continue DOMAIN
					}
					up = up2
				}

				// Identical IP from dynamic NAT is valid as subnet relation.
				ns := domain.natSet
				natSubnet := getNatNetwork(subnet, ns)
				if natSubnet.dynamic {
					natBignet := getNatNetwork(bignet, ns)
					if natBignet.dynamic &&
						natSubnet.ip.Equal(natBignet.ip) &&
						net.IP(natSubnet.mask).Equal(net.IP(natBignet.mask)) {
						continue
					}
				}

				// Found NAT domain, where networks are not in subnet relation.
				// Remember at attribute unstableNat for later check.
				u := bignet.unstableNat
				if u == nil {
					u = make(map[natSet]netList)
					bignet.unstableNat = u
				}
				u[ns] = append(u[ns], subnet)
			}
		}
	}

	// Secondary optimization substitutes a host or interface by its
	// largest valid supernet inside the same security zone. This
	// supernet has already been calculated and stored in
	// maxRoutingnet. But maxRoutingNet can't be used if it has
	// a subnet in some other security zone. In this case we have to
	// search again for a supernet without attribute hasOtherSubnet.
	// The result is stored in maxSecondarynet.
	for _, n := range networks {
		max := n.maxRoutingNet
		if max == nil {
			continue
		}

		// Disable maxRoutingnet if it has unstable NAT relation with
		// current subnet.
		// This test is only a rough estimation and should be refined
		// if to many valid optimizations would be disabled.
		if max.unstableNat != nil && n.nat != nil {
			n.maxRoutingNet = nil
			continue
		}
		if !max.hasOtherSubnet {
			n.maxSecondaryNet = max
			continue
		}
		up := n.up
		for up != nil {
			if up.hasOtherSubnet {
				break
			} else {
				if !up.isAggregate {
					n.maxSecondaryNet = up
				}
				up = up.up
			}
		}
	}
}

//############################################################################
// Returns: Lookup hash with domains as keys and partition ID as values.
// Result : NAT domains get different partition ID, if they belong to
//          parts of topology that are strictly separated by crypto
//          interfaces or partitioned toplology.
func findNatPartitions(domains []*natDomain) map[*natDomain]int {
	partitions := make(map[*natDomain]int)
	var markNatPartition func(*natDomain, int)
	markNatPartition = func(domain *natDomain, mark int) {
		if partitions[domain] != 0 {
			return
		}

		//debug("%s %s", mark, domain.name)
		partitions[domain] = mark
		for _, r := range domain.routers {
			for _, outDomain := range r.natDomains {
				if outDomain == domain {
					continue
				}
				markNatPartition(outDomain, mark)
			}
		}
	}
	mark := 1
	for _, domain := range domains {
		markNatPartition(domain, mark)
		mark++
	}
	return partitions
}

// Find subnet relation between networks in different NAT domains.
// Mark networks, having subnet in other zone: bignet->{has_other_subnet}
// 1. If set, this prevents secondary optimization.
// 2. If rule has src or dst with attribute {has_other_subnet},
//    it is later checked for missing supernets.
func FindSubnetsInNatDomain(domains []*natDomain) {
	diag.Progress(fmt.Sprintf("Finding subnets in %d NAT domains", len(domains)))

	// Mapping from NAT domain to ID of NAT partition.
	dom2Part := findNatPartitions(domains)

	part2Doms := make(map[int][]*natDomain)
	for _, dom := range domains {
		part := dom2Part[dom]
		part2Doms[part] = append(part2Doms[part], dom)
	}
	part2Nets := make(map[int]netList)
	for _, n := range allNetworks {
		if n.unnumbered || n.tunnel {
			continue
		}
		part := dom2Part[n.zone.natDomain]
		part2Nets[part] = append(part2Nets[part], n)
	}
	partList := make([]int, 0, len(part2Doms))
	for part, _ := range part2Doms {
		partList = append(partList, part)
	}
	sort.Ints(partList)
	for _, part := range partList {
		findSubnetsInNatDomain0(part2Doms[part], part2Nets[part])
	}
}

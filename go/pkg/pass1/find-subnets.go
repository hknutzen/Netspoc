package pass1

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/hknutzen/Netspoc/go/pkg/sorted"
	"golang.org/x/exp/maps"

	"go4.org/netipx"
)

func natName(n *network) string {
	name := n.descr
	if name == "" {
		name = n.name
	}
	return name
}

func processSubnetRelation(prefixIPMap map[int]map[netip.Addr]*network,
	work func(sub, big *network)) {

	prefixList := maps.Keys(prefixIPMap)
	sort.Slice(prefixList, func(i, j int) bool {
		// Go from smaller to larger networks, i.e big prefix value first.
		return prefixList[i] > prefixList[j]
	})
	for i, prefix := range prefixList {
		upperPrefixes := prefixList[i+1:]

		// No supernets available
		if len(upperPrefixes) == 0 {
			break
		}

		// Sort IP addresses to get deterministic warnings and ACLs.
		ipMap := prefixIPMap[prefix]
		ipList := maps.Keys(ipMap)
		sort.Slice(ipList, func(i, j int) bool {
			return ipList[i].Less(ipList[j])
		})
		for _, ip := range ipList {
			sub := ipMap[ip]

			// Find networks which include current subnet.
			// upperPrefixes holds prefixes of potential supernets.
			for _, p := range upperPrefixes {
				up, _ := ip.Prefix(p)
				if big, ok := prefixIPMap[p][up.Addr()]; ok {
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
func (c *spoc) checkSubnets(n, subnet *network, context string) {
	if n.isAggregate || subnet.isAggregate {
		return
	}
	ipp := subnet.ipp
	err := func(obj groupObj) {
		where := subnet.name
		if context != "" {
			where += " in " + context
		}
		c.warn("IP of %s overlaps with subnet %s", obj, where)
	}
INTF:
	for _, intf := range n.interfaces {
		if intf.ipType == hasIP {
			if ipp.Contains(intf.ip) {

				// NAT to an interface address (masquerading) is allowed.
				if tags := intf.bindNat; tags != nil {
					if tag2 := subnet.natTag; tag2 != "" {
						for _, tag := range tags {
							if tag == tag2 &&
								intf.ip == ipp.Addr() && ipp.IsSingleIP() {
								continue INTF
							}
						}
					}
				}
				err(intf)
			}
		}
	}
	for _, host := range n.hosts {
		if ip := host.ip; ip.IsValid() {
			if ipp.Contains(ip) {
				err(host)
			}
		} else if host.ipRange.Overlaps(netipx.RangeOfPrefix(ipp)) {
			err(host)
		}
	}
}

//###################################################################
// Find sub-networks
// Mark each network with the smallest network enclosing it.
//###################################################################

func (c *spoc) findSubnetsInZoneCluster0(z0 *zone) {

	// Add networks of zone cluster to prefixIPMap.
	prefixIPMap := make(map[int]map[netip.Addr]*network)
	add := func(n *network) {
		ipp := n.ipp
		ipMap := prefixIPMap[ipp.Bits()]
		if ipMap == nil {
			ipMap = make(map[netip.Addr]*network)
			prefixIPMap[ipp.Bits()] = ipMap
		}

		// Found two different networks with identical IP/mask.
		if other := ipMap[ipp.Addr()]; other != nil {
			c.err("%s and %s have identical IP/mask in %s",
				other.name, n.name, z0.name)
		} else {

			// Store original network under IP/mask.
			ipMap[ipp.Addr()] = n
		}
	}
	for _, n := range z0.ipPrefix2aggregate {
		add(n)
	}
	for _, z := range z0.cluster {
		for _, n := range z.networks {
			add(n)
		}
	}

	// Process networks of zone cluster, that are in direct subnet relation.
	processSubnetRelation(prefixIPMap, func(sub, big *network) {

		// Collect subnet relation.
		sub.up = big

		// Propagate subnet relation of aggregate to cluster.
		if sub.isAggregate && len(z0.cluster) > 1 {
			for _, z := range z0.cluster {
				sub2 := z.ipPrefix2aggregate[sub.ipp]
				sub2.up = big
			}
		}

		c.checkSubnets(big, sub, "")
	})
}

func updateSubnetRelation0(z *zone) {
	prefixIPMap := make(map[int]map[netip.Addr]*network)
	add := func(n *network) {
		n.up = nil // reset previous value of .up relation
		ipp := n.ipp
		ipMap := prefixIPMap[ipp.Bits()]
		if ipMap == nil {
			ipMap = make(map[netip.Addr]*network)
			prefixIPMap[ipp.Bits()] = ipMap
		}
		ipMap[ipp.Addr()] = n
	}
	for _, n := range z.networks {
		add(n)
	}
	for _, n := range z.ipPrefix2aggregate {
		add(n)
	}

	// Process networks of zone, that are in direct subnet relation.
	processSubnetRelation(prefixIPMap, func(sub, big *network) {
		sub.up = big
	})
}

// Fill n.networks relation and remove networks from z.networks, that
// are subnet of some other network.
func updateNetworksRelation(z *zone) {
	j := 0
NET:
	for _, n := range z.networks {
		for big := n.up; big != nil; big = big.up {
			big.networks.push(n)
			// Current network has some supernet, discard.
			if !big.isAggregate {
				continue NET
			}
		}
		// Current network has no supernet, retain.
		z.networks[j] = n
		j++
	}
	z.networks = z.networks[:j]

	// It is valid to have an aggregate in a zone which has no matching
	// networks. This can be useful to add optimization rules at an
	// intermediate device.
}

// Find subnet relation between networks inside zone cluster.
// - subnet.up = bignet;
func (c *spoc) findSubnetsInZoneCluster() {
	seen := make(map[*zone]bool)
	for _, z := range c.allZones {
		if len(z.cluster) > 1 {
			if seen[z.cluster[0]] {
				continue
			}
			seen[z.cluster[0]] = true
		}
		c.findSubnetsInZoneCluster0(z)
	}
}

// Update subnet relation from networks inside zone cluster
// to networks inside zone.
// - subnet.up = bignet;
func (c *spoc) updateSubnetRelation() {
	for _, z := range c.allZones {
		if len(z.cluster) > 1 {
			updateSubnetRelation0(z)
		}
		updateNetworksRelation(z)
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

func setMaxRoutingNet(z *zone) {
	var setMax func(big *network, l netList)
	setMax = func(big *network, l netList) {
	SUB:
		for _, sub := range l {
			// If larger network is hidden at some place, only use it for
			// routing, if original network is hidden there as well.
			// We don't need to check here that subnet relation is
			// maintained for NAT addresses.
			// That is enforced later in findSubnetsInNatDomain.
			for tag, upNatInfo := range big.nat {
				// All definitions of a single NAT tag have been checked
				// to be of same type, hence we only need to check
				// sub.nat[tag] for nil.
				if upNatInfo.hidden && sub.nat[tag] == nil {
					setMax(sub, sub.networks)
					continue SUB
				}
			}
			sub.maxRoutingNet = big
			setMax(big, sub.networks)
		}
	}
	// Traverse toplevel networks of zone.
	for _, big := range z.networks {
		setMax(big, big.networks)
	}
}

func (c *spoc) findSubnetsInNatDomain0(domains []*natDomain, networks netList) {

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
	// .isIn and .identical.

	// Mapping prefix -> IP -> Network|NAT Network.
	prefixIPMap := make(map[int]map[netip.Addr]*network)

	// Mapping from one network|NAT network to networks with identical
	// IP address.
	identical := make(map[*network]netList)

	for _, nn := range natNetworks {
		ipp := nn.ipp
		ipMap := prefixIPMap[ipp.Bits()]
		if ipMap == nil {
			ipMap = make(map[netip.Addr]*network)
			prefixIPMap[ipp.Bits()] = ipMap
		}
		if other := ipMap[ipp.Addr()]; other != nil {

			// Bild lists of identical networks.
			if identical[other] == nil {
				identical[other] = netList{other}
			}
			identical[other] = append(identical[other], nn)
		} else {
			ipMap[ipp.Addr()] = nn
		}
	}

	// Calculate .isIn relation from IP addresses;
	// This includes all addresses of all networks in all NAT domains.
	isIn := make(map[*network]*network)
	processSubnetRelation(prefixIPMap, func(sub, big *network) {
		isIn[sub] = big
	})

	// 2. step:
	// Analyze .isIn and .Identical relation for different NAT domains.

	// Mapping from subnet to bignet in same zone.
	// Bignet must be marked, if subnet is marked later with .hasOtherSubnet.
	pendingOtherSubnet := make(map[*network]netList)
	var markNetworkAndPending func(*network)
	markNetworkAndPending = func(n *network) {
		if n.hasOtherSubnet {
			return
		}
		n.hasOtherSubnet = true
		if l, ok := pendingOtherSubnet[n]; ok {
			delete(pendingOtherSubnet, n)
			for _, e := range l {
				markNetworkAndPending(e)
			}
		}
	}
	type netPair [2]*network
	subnetInZone := make(map[netPair]map[*natDomain]bool)
	identSeen := make(netMap)
	relationSeen := make(map[netPair]bool)
	for _, domain := range domains {
		//debug("%s", domain.name)
		natMap := domain.natMap

		// Mark networks visible in current NAT domain.
		// - Real network is visible, if none of its NAT tag are active.
		// - NAT network is visible if its NAT tag is active.
		// - Located in same NAT partition as current NAT domain.
		// - Not hidden.
		visible := make(map[*network]bool)
		for _, n := range networks {
			if natNetwork := getNatNetwork(n, natMap); !natNetwork.hidden {
				visible[natNetwork] = true
				//debug("visible: %s", natName(natNetwork))
			}
		}

		// Mark and analyze networks having identical IP/mask in
		// current NAT domain.
		hasIdentical := make(map[*network]bool)
		for n1, l := range identical {
			var filtered netList
			for _, n := range l {
				if visible[n] {
					filtered.push(n)
				}
			}
			if len(filtered) <= 1 {
				continue
			}
			for _, n := range filtered {
				hasIdentical[n] = true
			}

			// If list has been fully analyzed once, don't check it again.
			if identSeen[n1] {
				continue
			}
			if len(filtered) == len(l) {
				identSeen[n1] = true
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
					//debug("identical %s %s", n, other)
				} else if natOther.dynamic && natNetwork.dynamic {

					// Dynamic NAT of different networks to a single new
					// IP/mask is OK between different zones.
					// But not if both networks and NAT domain are located
					// in same zone cluster.
					cl := n.zone.cluster[0]
					if other.zone.cluster[0] == cl {
						for _, z := range domain.zones {
							if z.cluster[0] == cl {
								c.err("%s and %s have identical IP/mask in %s",
									n, other, z)
								break
							}
						}
					}
				} else if other.loopback && natNetwork.dynamic {
					if !natToLoopbackOk(other, natNetwork) {
						error = true
					}
				} else if natOther.dynamic && n.loopback {
					if !natToLoopbackOk(n, natOther) {
						error = true
					}
				} else if n.ipType == bridgedIP && other.ipType == bridgedIP {

					// Parts of bridged network have identical IP by design.
				} else {
					error = true
				}
				if error {
					c.err("%s and %s have identical IP/mask\n"+
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
				foundOther := false
				for _, n := range identical[natSubnet] {
					if visible[n] {
						natSubnet = n
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
				for _, n := range identical[natBignet] {
					if visible[n] {
						natBignet = n
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
			collect := func(subnet *network) {
				z := subnet.zone
				natBignet := natBignet
				for {
					bignet := origNet[natBignet]
					if visible[natBignet] && bignet.zone == z {
						domMap := subnetInZone[netPair{bignet, subnet}]
						if domMap == nil {
							domMap = make(map[*natDomain]bool)
							subnetInZone[netPair{bignet, subnet}] = domMap
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
			if l := identical[natSubnet]; l != nil {
				for _, n := range l {
					if visible[n] {
						collect(origNet[n])
					}
				}
			} else {
				collect(subnet)
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
			if bignet.zone == subnet.zone {
				if subnet.hasOtherSubnet || hasIdentical[subnet] {
					bignet.hasOtherSubnet = true
				} else {
					pendingOtherSubnet[subnet] =
						append(pendingOtherSubnet[subnet], bignet)
				}
			} else {
				// Mark network having subnet in other zone.
				markNetworkAndPending(bignet)
				//debug("%s > %s", bignet, subnet)

				// Mark aggregate that has other *supernet*.
				// In this situation, addresses of aggregate
				// are part of supernet and located in other
				// zone.
				// But ignore the internet and non matching aggregate.
				if subnet.isAggregate && bignet.ipp.Bits() != 0 {
					markNetworkAndPending(subnet)
					//debug("%s ~ %s", subnet, bignet)
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
				for _, identNet := range identical[natBignet] {
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

			if !natSubnet.isLayer3 {
				subnet.subnetOfUsed = true
				if printType := c.conf.CheckSubnets; printType != "" &&
					// Take original bignet, because currently
					// there's no method to specify a natted network
					// as value of subnet_of.
					natSubnet.subnetOf != bignet &&
					!(bignet.hasSubnets &&
						(bignet.ipp.Bits() == 0 ||
							zoneEq(bignet.zone, subnet.zone) ||
							isLoopbackAtZoneBorder(subnet, bignet))) {

					// Prevent multiple error messages in
					// different NAT domains.
					if natSubnet.subnetOf == nil {
						natSubnet.subnetOf = bignet
					}
					c.warnOrErr(printType,
						"%s is subnet of %s\n"+
							" in %s.\n"+
							" If desired, declare attribute 'subnet_of'",
						natName(natSubnet), natName(natBignet), domain.name)
				}
			}

			if bignet.zone != subnet.zone {
				c.checkSubnets(natBignet, natSubnet, domain.name)
			}
		}
	}

	for pair, dom2isSubnet := range subnetInZone {
		bignet, subnet := pair[0], pair[1]

		// Ignore relation, if both are aggregates,
		// because IP addresses of aggregates can't be changed by NAT.
		if subnet.isAggregate && bignet.isAggregate {
			continue
		}

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
			m := domain.natMap
			natBignet := getNatNetwork(bignet, m)
			if natBignet.hidden {
				continue
			}
			natSubnet := getNatNetwork(subnet, m)
			if natSubnet.hidden {
				continue
			}

			// Identical IP from dynamic NAT is valid as subnet relation.
			if natSubnet.dynamic && natBignet.dynamic &&
				natSubnet.ipp == natBignet.ipp {

				continue
			}

			// Also check transient subnet relation.
			up := subnet
			for {
				up2 := up.up
				// up2 can't become nil because subnet and bignet are
				// known to be in .up relation in zone.
				if !subnetInZone[netPair{up2, up}][domain] {
					break
				}
				if up2 == bignet {
					continue DOMAIN
				}
				up = up2
			}

			// Found NAT domain, where networks are not in subnet relation.
			// Remember at attribute unstableNat for later check.
			u := bignet.unstableNat
			if u == nil {
				u = make(map[*natDomain]netList)
				bignet.unstableNat = u
			}
			u[domain] = append(u[domain], subnet)
		}
	}

	// Secondary optimization substitutes a host or interface by its
	// largest valid supernet inside the same security zone. This
	// supernet has already been calculated and stored in
	// .maxRoutingNet. But .maxRoutingNet can't be used if it has
	// a subnet in some other security zone. In this case we have to
	// search again for a supernet without attribute .hasOtherSubnet.
	// The result is stored in .maxSecondaryNet.
	for _, n := range networks {
		max := n.maxRoutingNet
		if max == nil {
			continue
		}

		// Disable maxRoutingnet if it has unstable NAT relation with
		// current subnet.
		// This test is only a rough estimation and should be refined
		// if too many valid optimizations would be disabled.
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

func isLoopbackAtZoneBorder(sub, big *network) bool {
	if sub.loopback {
		z := big.zone
		for _, intf := range sub.interfaces[0].router.interfaces {
			if z2 := intf.zone; z2 != nil && zoneEq(z, z2) {
				return true
			}
		}
	}
	return false
}

func (c *spoc) findUselessSubnetOf() {
	for _, n := range c.allNetworks {
		if bignet := n.subnetOf; bignet != nil && !n.subnetOfUsed {
			c.warn("Useless 'subnet_of = %s' at %s", bignet, n)
		}
	}
}

// ############################################################################
// Returns: Map with domains as keys and partition ID as values.
// Result : NAT domains get different partition ID, if they belong to
//
//	parts of topology that are strictly separated by crypto
//	interfaces or partitioned toplology.
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
// Mark networks, having subnet in other zone: bignet.hasOtherSubnet
//  1. If set, this prevents secondary optimization.
//  2. If rule has src or dst with attribute .hasOtherSubnet,
//     it is later checked for missing supernets.
func (c *spoc) findSubnetsInNatDomain(domains []*natDomain) {
	c.progress(fmt.Sprintf("Finding subnets in %d NAT domains", len(domains)))
	for _, z := range c.allZones {
		setMaxRoutingNet(z)
	}

	// Mapping from NAT domain to ID of NAT partition.
	dom2Part := findNatPartitions(domains)

	part2Doms := make(map[int][]*natDomain)
	for _, dom := range domains {
		part := dom2Part[dom]
		part2Doms[part] = append(part2Doms[part], dom)
	}
	part2Nets := make(map[int]netList)
	for _, n := range c.allNetworks {
		if n.ipType == unnumberedIP || n.ipType == tunnelIP {
			continue
		}
		part := dom2Part[n.zone.natDomain]
		part2Nets[part] = append(part2Nets[part], n)
	}

	// Sorts error messages before output.
	c.sortedSpoc(func(c *spoc) {
		for _, part := range sorted.Keys(part2Doms) {
			c.findSubnetsInNatDomain0(part2Doms[part], part2Nets[part])
		}
	})
	c.findUselessSubnetOf()
}

package pass1

import (
	"fmt"
	"github.com/Sereal/Sereal/Go/sereal"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"
)

type xAny interface{}
type xMap = map[string]interface{}
type xSlice = []interface{}

func getBool(x xAny) bool {
	switch b := x.(type) {
	case nil:
		return false
	case string:
		return b != "" && b != "0"
	case []byte:
		s := string(b[:])
		return s != "" && s != "0"
	case int:
		return b != 0
	default:
		return true
	}
}

func getInt(x xAny) int {
	switch i := x.(type) {
	case nil:
		return 0
	case string:
		n, err := strconv.Atoi(i)
		if err != nil {
			panic(fmt.Errorf("Can't covert to int: %v", i))
		}
		return n
	case int:
		return i
	default:
		panic(fmt.Errorf("Expected int but got %v", i))
	}
}

func getIP(x xAny) net.IP {
	s := getString(x)
	return net.IP(s)
}
func getIPs(x xAny) []net.IP {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	result := make([]net.IP, len(a))
	for i, elt := range a {
		result[i] = getIP(elt)
	}
	return result
}

func getString(x xAny) string {
	switch a := x.(type) {
	case nil:
		return ""
	case string:
		return a
	case []byte:
		return string(a[:])
	case int:
		return fmt.Sprint(a)
	default:
		panic(fmt.Errorf("Expected string or byte slice but got %v", a))
	}
}
func getStrings(x xAny) []string {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	result := make([]string, len(a))
	for i, elt := range a {
		result[i] = getString(elt)
	}
	return result
}
func getMapStringString(x xAny) map[string]string {
	m := getMap(x)
	n := make(map[string]string)
	for k, v := range m {
		n[getString(k)] = getString(v)
	}
	return n
}

func getRegexp(x xAny) *regexp.Regexp {
	s := getString(x)
	if s == "" {
		return nil
	}
	r := regexp.MustCompile(s)
	return r
}

func getSlice(x xAny) xSlice {
	switch a := x.(type) {
	case nil:
		return make(xSlice, 0)
	case xSlice:
		return a
	case *xSlice:
		return *a
	default:
		panic(fmt.Errorf("Expected xSlice or *xSlice but got %v", a))
	}
}

func getMap(x xAny) xMap {
	switch m := x.(type) {
	case nil:
		return make(xMap)
	case xMap:
		return m
	case *xMap:
		return *m
	default:
		panic(fmt.Errorf("Expected xMap or *xMap but got %v", m))
	}
}

func (x *ipObj) setCommon(m xMap) {
	x.name = getString(m["name"])
	s := getString(m["ip"])
	switch s {
	case "unnumbered":
		x.unnumbered = true
	case "negotiated":
		x.negotiated = true
	case "short":
		x.short = true
	case "tunnel":
		x.tunnel = true
	case "bridged":
		x.bridged = true
	case "":
		break
	default:
		x.ip = net.IP(s)
	}
	x.owner = convOwner(m["owner"])
	if up, ok := m["up"]; ok {
		x.up = convSomeObj(up)
	}
}
func (x *netObj) setCommon(m xMap) {
	x.ipObj.setCommon(m)
	x.bindNat = getStrings(m["bind_nat"])
	x.network = convNetwork(m["network"])
	x.nat = convIPNat(m["nat"])
}

func convNetNat(x xAny) natMap {
	m := getMap(x)
	n := make(map[string]*network)
	for tag, natNet := range m {
		n[tag] = convNetwork(natNet)
	}
	return n
}

func convIPNat(x xAny) map[string]net.IP {
	m := getMap(x)
	n := make(map[string]net.IP)
	for tag, x := range m {
		n[tag] = getIP(x)
	}
	return n
}

func convNetwork(x xAny) *network {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if n, ok := m["ref"]; ok {
		return n.(*network)
	}
	n := new(network)
	m["ref"] = n
	n.setCommon(m)
	n.bridged = getBool(m["bridged"])
	n.attr = convAttr(m)
	if m["mask"] != nil {
		n.mask = m["mask"].([]byte)
	}
	if list, ok := m["subnets"]; ok {
		xSubnets := list.(xSlice)
		subnets := make([]*subnet, len(xSubnets))
		for i, xSubnet := range xSubnets {
			subnets[i] = convSubnet(xSubnet)
		}
		n.subnets = subnets
	}
	n.descr = getString(m["descr"])
	n.interfaces = convRouterIntfs(m["interfaces"])
	n.zone = convZone(m["zone"])
	n.disabled = getBool(m["disabled"])
	n.hasOtherSubnet = getBool(m["has_other_subnet"])
	n.hasSubnets = getBool(m["has_subnets"])
	n.hosts = convHosts(m["hosts"])
	n.isAggregate = getBool(m["is_aggregate"])
	n.isLayer3 = getBool(m["is_layer3"])
	n.loopback = getBool(m["loopback"])
	n.managedHosts = convRouterIntfs(m["managed_hosts"])
	n.maxRoutingNet = convNetwork(m["max_routing_net"])
	n.maxSecondaryNet = convNetwork(m["max_secondary_net"])
	n.networks = convNetworks(m["networks"])
	n.nat = convNetNat(m["nat"])
	n.networks = convNetworks(m["networks"])
	n.dynamic = getBool(m["dynamic"])
	n.hidden = getBool(m["hidden"])
	n.ipV6 = getBool(m["ipv6"])
	n.natTag = getString(m["nat_tag"])
	n.certId = getString(m["cert_id"])
	if x, ok := m["filter_at"]; ok {
		m := getMap(x)
		p := make(map[int]bool)
		for x, _ := range m {
			p[getInt(x)] = true
		}
		n.filterAt = p
	}
	n.hasIdHosts = getBool(m["has_id_hosts"])
	n.invisible = getBool(m["invisible"])
	n.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	n.subnetOf = convNetwork(m["subnet_of"])
	n.up = convNetwork(m["up"])
	return n
}
func convNetworks(x xAny) netList {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	networks := make(netList, len(a))
	for i, x := range a {
		networks[i] = convNetwork(x)
	}
	return networks
}

func convSubnet(x xAny) *subnet {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*subnet)
	}
	s := new(subnet)
	m["ref"] = s
	s.setCommon(m)
	s.mask = m["mask"].([]byte)
	s.id = getString(m["id"])
	s.ldapId = getString(m["ldap_id"])
	s.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	return s
}
func convSubnets(x xAny) []*subnet {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	subnets := make([]*subnet, len(a))
	for i, x := range a {
		subnets[i] = convSubnet(x)
	}
	return subnets
}

func convHost(x xAny) *host {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*host)
	}
	o := new(host)
	m["ref"] = o
	o.setCommon(m)
	if x, ok := m["range"]; ok {
		a := getSlice(x)
		o.ipRange = [2]net.IP{getIP(a[0]), getIP(a[1])}
	}
	o.id = getString(m["id"])
	o.ldapId = getString(m["ldap_id"])
	o.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	o.subnets = convSubnets(m["subnets"])
	return o
}
func convHosts(x xAny) []*host {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	hosts := make([]*host, len(a))
	for i, x := range a {
		hosts[i] = convHost(x)
	}
	return hosts
}

func convNatSet(x xAny) natSet {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if n, ok := m[":ref"]; ok {
		return n.(natSet)
	}
	n := make(map[string]bool)
	for tag := range m {
		n[tag] = true
	}
	m[":ref"] = natSet(&n)
	return &n
}

func convModel(x xAny) *model {
	m := getMap(x)
	if d, ok := m["ref"]; ok {
		return d.(*model)
	}
	d := new(model)
	m["ref"] = d
	d.commentChar = getString(m["comment_char"])
	d.class = getString(m["class"])
	d.crypto = getString(m["crypto"])
	d.doAuth = getBool(m["do_auth"])
	d.canObjectgroup = getBool(m["can_objectgroup"])
	d.cryptoInContext = getBool(m["crypto_in_context"])
	d.filter = getString(m["filter"])
	d.logModifiers = getMapStringString(m["log_modifiers"])
	d.needAcl = getBool(m["need_acl"])
	d.hasIoAcl = getBool(m["has_io_acl"])
	d.noCryptoFilter = getBool(m["no_crypto_filter"])
	d.printRouterIntf = getBool(m["print_interface"])
	d.routing = getString(m["routing"])
	d.stateless = getBool(m["stateless"])
	d.statelessSelf = getBool(m["stateless_self"])
	d.statelessICMP = getBool(m["stateless_icmp"])
	d.usePrefix = getBool(m["use_prefix"])
	return d
}

func convLoop(x xAny) *loop {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if l, ok := m["ref"]; ok {
		return l.(*loop)
	}
	l := new(loop)
	m["ref"] = l
	l.exit = convPathObj(m["exit"])
	l.distance = getInt(m["distance"])
	l.clusterExit = convPathObj(m["cluster_exit"])
	return l
}

func convRouter(x xAny) *router {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*router)
	}
	r := new(router)
	m["ref"] = r
	r.name = getString(m["name"])
	r.deviceName = getString(m["device_name"])
	r.managed = getString(m["managed"])
	r.semiManaged = getBool(m["semi_managed"])
	r.routingOnly = getBool(m["routing_only"])
	r.adminIP = getStrings(m["admin_ip"])
	r.model = convModel(m["model"])
	r.log = getMapStringString(m["log"])
	r.logDeny = getBool(m["log_deny"])
	r.localMark = getInt(m["local_mark"])
	r.interfaces = convRouterIntfs(m["interfaces"])
	r.origIntfs = convRouterIntfs(m["orig_interfaces"])
	r.crosslinkIntfs = convRouterIntfs(m["crosslink_interfaces"])
	r.distance = getInt(m["distance"])
	if x, ok := m["filter_only"]; ok {
		a := getSlice(x)
		b := make([]net.IPNet, len(a))
		for i, xPair := range a {
			pair := getSlice(xPair)
			ip := getIP(pair[0])
			mask := getIP(pair[1])
			b[i] = net.IPNet{IP: ip, Mask: net.IPMask(mask)}
		}
		r.filterOnly = b
	}
	r.generalPermit = convProtos(m["general_permit"])
	r.loop = convLoop(m["loop"])
	r.natDomains = convNATDomains(m["nat_domains"])
	r.needProtect = getBool(m["need_protect"])
	r.noGroupCode = getBool(m["no_group_code"])
	r.noInAcl = convRouterIntf(m["no_in_acl"])
	if x, ok := m["no_secondary_opt"]; ok {
		m := getMap(x)
		n := make(map[*network]bool)
		for _, x := range m {
			n[convNetwork(x)] = true
		}
		r.noSecondaryOpt = n
	}
	r.hardware = convHardwareList(m["hardware"])
	r.origHardware = convHardwareList(m["orig_hardware"])
	r.owner = convOwner(m["owner"])
	r.ipvMembers = convRouters(m["ipv_members"])
	r.vrfMembers = convRouters(m["vrf_members"])
	r.origRouter = convRouter(m["orig_router"])
	r.policyDistributionPoint = convHost(m["policy_distribution_point"])
	r.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	r.toZone1 = convRouterIntf(m["to_zone1"])
	r.trustPoint = getString(m["trust_point"])
	r.ipV6 = getBool(m["ipv6"])
	r.vrf = getString(m["vrf"])

	// Add unique zone to each managed router.
	// This represents the router itself.
	if r.managed != "" {
		r.zone = new(zone)
	}
	return r
}
func convRouters(x xAny) []*router {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	routers := make([]*router, len(a))
	for i, x := range a {
		routers[i] = convRouter(x)
	}
	return routers
}

func convPathRestrict(x xAny) *pathRestriction {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*pathRestriction)
	}
	r := new(pathRestriction)
	m["ref"] = r
	return r
}
func convPathRestricts(x xAny) []*pathRestriction {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	list := make([]*pathRestriction, len(a))
	for i, x := range a {
		list[i] = convPathRestrict(x)
	}
	return list
}

func convRouterIntf(x xAny) *routerIntf {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*routerIntf)
	}
	i := new(routerIntf)
	m["ref"] = i
	i.setCommon(m)
	i.router = convRouter(m["router"])
	i.crypto = convCrypto(m["crypto"])
	i.dhcpClient = getBool(m["dhcp_client"])
	i.dhcpServer = getBool(m["dhcp_server"])
	i.hub = convCryptoList(m["hub"])
	i.spoke = convCrypto(m["spoke"])
	i.id = getString(m["id"])
	i.isHub = getBool(m["is_hub"])
	if i.router != nil && (i.router.managed != "" || i.router.routingOnly) {
		i.hardware = convHardware(m["hardware"])
	}
	i.layer3Intf = convRouterIntf(m["layer3_interface"])
	i.loop = convLoop(m["loop"])
	i.loopback = getBool(m["loopback"])
	i.loopZoneBorder = getBool(m["loop_zone_border"])
	i.mainIntf = convRouterIntf(m["main_interface"])
	i.natSet = convNatSet(m["nat_set"])
	i.origMain = convRouterIntf(m["orig_main"])
	i.pathRestrict = convPathRestricts(m["path_restrict"])
	i.peer = convRouterIntf(m["peer"])
	i.peerNetworks = convNetworks(m["peer_networks"])
	i.realIntf = convRouterIntf(m["real_interface"])
	i.redundancyIntfs = convRouterIntfs(m["redundancy_interfaces"])
	i.redundancyType = getString(m["redundancy_type"])
	i.redundant = getBool(m["redundant"])
	i.reroutePermit = convSomeObjects(m["reroute_permit"])
	if x, ok := m["routes"]; ok {
		m1 := getMap(x)
		n1 := make(map[*routerIntf]netMap)
		m2 := getMap(m["hopref2obj"])
		n2 := make(map[string]*routerIntf)
		for ref, intf := range m2 {
			n2[getString(ref)] = convRouterIntf(intf)
		}
		for ref, nMap := range m1 {
			m := getMap(nMap)
			n := make(netMap)
			for _, x := range m {
				n[convNetwork(x)] = true
			}
			n1[n2[getString(ref)]] = n
		}
		i.routes = n1
	}
	i.routing = convRouting(m["routing"])
	if x, ok := m["id_rules"]; ok {
		m := getMap(x)
		n := make(map[string]*idIntf)
		for id, idIntf := range m {
			n[getString(id)] = convIdIntf(idIntf)
		}
		i.idRules = n
	}
	i.toZone1 = convPathObj(m["to_zone1"])
	i.zone = convZone(m["zone"])
	return i
}
func convRouterIntfs(x xAny) []*routerIntf {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	interfaces := make([]*routerIntf, len(a))
	for i, x := range a {
		interfaces[i] = convRouterIntf(x)
	}
	return interfaces
}

func convIdIntf(x xAny) *idIntf {
	m := getMap(x)
	z := new(idIntf)
	z.src = convSubnet(m["src"])
	z.routerIntf = convRouterIntf(x)
	return z
}

func convRouting(x xAny) *routing {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*routing)
	}
	r := new(routing)
	m["ref"] = r
	r.name = getString(m["name"])
	r.prt = convProto(m["prt"])
	r.mcast = convMcastInfo(m)
	return r
}

func convMcastInfo(m xMap) mcastInfo {
	var i mcastInfo
	i.v4 = getStrings(m["mcast"])
	i.v6 = getStrings(m["mcast6"])
	return i
}

func convHardware(x xAny) *hardware {
	m := getMap(x)
	if i, ok := m["ref"]; ok {
		return i.(*hardware)
	}
	h := new(hardware)
	m["ref"] = h
	h.interfaces = convRouterIntfs(m["interfaces"])
	h.crosslink = getBool(m["crosslink"])
	h.loopback = getBool(m["loopback"])
	h.name = getString(m["name"])
	h.natSet = convNatSet(m["nat_set"])
	h.dstNatSet = convNatSet(m["dst_nat_set"])
	h.needOutAcl = getBool(m["need_out_acl"])
	h.noInAcl = getBool(m["no_in_acl"])
	return h
}
func convHardwareList(x xAny) []*hardware {
	a := getSlice(x)
	l := make([]*hardware, len(a))
	for i, x := range a {
		l[i] = convHardware(x)
	}
	return l
}

func convPathObj(x xAny) pathObj {
	m := getMap(x)

	// Don't check name, because managed host is also stored as interface.
	if _, ok := m["networks"]; ok {
		return convZone(x)
	}
	return convRouter(x)
}

func convPathStore(x xAny) pathStore {
	m := getMap(x)

	// Don't check name, because managed host is also stored as interface.
	if _, ok := m["router"]; ok {
		return convRouterIntf(x)
	}
	if _, ok := m["networks"]; ok {
		return convZone(x)
	}
	return convRouter(x)
}

func convSomeObj(x xAny) someObj {
	m := getMap(x)

	// Don't check name, because managed host is also stored as interface.
	if _, ok := m["router"]; ok {
		return convRouterIntf(x)
	}
	if _, ok := m["network"]; ok {
		return convSubnet(x)
	}
	return convNetwork(x)
}
func convSomeObjects(x xAny) []someObj {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	objects := make([]someObj, len(a))
	for i, x := range a {
		objects[i] = convSomeObj(x)
	}
	return objects
}

func convSrvObj(x xAny) srvObj {
	m := getMap(x)

	// Don't check name, because managed host is also stored as interface.
	if _, ok := m["router"]; ok {
		return convRouterIntf(x)
	}
	if _, ok := m["network"]; ok {
		return convHost(x)
	}
	if _, ok := m["ip"]; ok {
		return convNetwork(x)
	}
	// Ignore area; was rejected with error message any way.
	return nil
}
func convSrvObjects(x xAny) []srvObj {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	objects := make([]srvObj, len(a))
	j := 0
	for _, x := range a {
		if obj := convSrvObj(x); obj != nil {
			objects[j] = obj
			j++
		}
	}
	objects = objects[0:j]
	return objects
}

var attrList []string = []string{"overlaps", "unknown_owner", "multi_owner", "has_unenforceable"}

func convAttr(m xMap) map[string]string {
	var result map[string]string
	for _, s := range attrList {
		if a, ok := m[s]; ok {
			if result == nil {
				result = make(map[string]string)
			}
			result[s] = getString(a)
		}
	}
	return result
}

func convRouterAttributes(x xAny) *routerAttributes {
	if x == nil {
		return nil
	}
	m := getMap(x)
	a := new(routerAttributes)
	a.name = getString(m["name"])
	a.owner = convOwner(m["owner"])
	return a
}

func convArea(x xAny) *area {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*area)
	}
	a := new(area)
	m["ref"] = a
	a.name = getString(m["name"])
	a.inArea = convArea(m["in_area"])
	a.attr = convAttr(m)
	a.managedRouters = convRouters(m["managed_routers"])
	a.owner = convOwner(m["owner"])
	a.routerAttributes = convRouterAttributes(m["router_attributes"])
	a.watchingOwner = convOwner(m["watching_owner"])
	a.zones = convZones(m["zones"])
	return a
}
func convAreas(x xAny) []*area {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	l := make([]*area, len(a))
	for i, x := range a {
		l[i] = convArea(x)
	}
	return l
}

func convZone(x xAny) *zone {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*zone)
	}
	z := new(zone)
	m["ref"] = z
	z.name = getString(m["name"])
	z.networks = convNetworks(m["networks"])
	z.attr = convAttr(m)
	z.distance = getInt(m["distance"])
	z.inArea = convArea(m["in_area"])
	z.interfaces = convRouterIntfs(m["interfaces"])
	z.ipmask2aggregate = convNetNat(m["ipmask2aggregate"])
	z.isTunnel = getBool(m["is_tunnel"])
	z.loop = convLoop(m["loop"])
	z.natDomain = convNATDomain(m["nat_domain"])
	z.noCheckSupernetRules = getBool(m["no_check_supernet_rules"])
	z.partition = getString(m["partition"])
	z.toZone1 = convRouterIntf(m["to_zone1"])
	z.zoneCluster = convZones(m["zone_cluster"])
	return z
}
func convZones(x xAny) []*zone {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	l := make([]*zone, len(a))
	for i, x := range a {
		l[i] = convZone(x)
	}
	return l
}

func convNATDomain(x xAny) *natDomain {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*natDomain)
	}
	d := new(natDomain)
	m["ref"] = d
	d.name = getString(m["name"])
	d.natSet = convNatSet(m["nat_set"])
	d.routers = convRouters(m["routers"])
	d.zones = convZones(m["zones"])
	return d
}
func convNATDomains(x xAny) []*natDomain {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	l := make([]*natDomain, len(a))
	for i, x := range a {
		l[i] = convNATDomain(x)
	}
	return l
}

func convOwner(x xAny) *owner {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*owner)
	}
	o := new(owner)
	m["ref"] = o
	o.name = getString(m["name"])
	o.showAll = getBool(m["show_all"])
	return o
}
func convOwnerMap(x xAny) map[string]*owner {
	m := getMap(x)
	n := make(map[string]*owner)
	for name, elt := range m {
		n[name] = convOwner(elt)
	}
	return n
}

func convModifiers(x xAny) modifiers {
	m := getMap(x)
	var n modifiers
	if _, ok := m["reversed"]; ok {
		n.reversed = true
	}
	if _, ok := m["stateless"]; ok {
		n.stateless = true
	}
	if _, ok := m["oneway"]; ok {
		n.oneway = true
	}
	if _, ok := m["src_net"]; ok {
		n.srcNet = true
	}
	if _, ok := m["dst_net"]; ok {
		n.dstNet = true
	}
	if _, ok := m["overlaps"]; ok {
		n.overlaps = true
	}
	if _, ok := m["no_check_supernet_rules"]; ok {
		n.noCheckSupernetRules = true
	}
	return n
}

func convProto(x xAny) *proto {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*proto)
	}
	p := new(proto)
	m["ref"] = p
	p.name = getString(m["name"])
	p.proto = getString(m["proto"])
	if t, ok := m["type"]; ok {
		p.icmpType = t.(int)
	} else {
		p.icmpType = -1
	}
	if c, ok := m["code"]; ok {
		p.icmpCode = c.(int)
	} else {
		p.icmpCode = -1
	}
	if m, ok := m["modifiers"]; ok {
		p.modifiers = convModifiers(m)
	}
	if list, ok := m["range"]; ok {
		a := getSlice(list)
		p.ports = [2]int{a[0].(int), a[1].(int)}
	}
	if _, ok := m["established"]; ok {
		p.established = true
	}
	if u, ok := m["up"]; ok {
		p.up = convProto(u)
	}
	p.src = convProto(m["src_range"])
	p.dst = convProto(m["dst_range"])
	p.main = convProto(m["main"])
	p.isUsed = getBool(m["is_used"])
	return p
}
func convProtos(x xAny) []*proto {
	a := getSlice(x)
	list := make([]*proto, len(a))
	for i, x := range a {
		list[i] = convProto(x)
	}
	return list
}
func convProtoMap(x xAny) map[string]*proto {
	m := getMap(x)
	n := make(map[string]*proto)
	for name, xProto := range m {
		n[name] = convProto(xProto)
	}
	return n
}

func convProtoLookup(x xAny) protoLookup {
	m := getMap(x)
	var n protoLookup
	n.ip = convProto(m["ip"])
	n.icmp = convProtoMap(m["icmp"])
	n.tcp = convProtoMap(m["tcp"])
	n.udp = convProtoMap(m["udp"])
	n.proto = convProtoMap(m["proto"])
	return n
}

func convProtoOrName(x xAny) protoOrName {
	switch u := x.(type) {
	case xSlice, *xSlice:
		return getStrings(x)
	case xMap, *xMap:
		return convProto(x)
	default:
		panic(fmt.Errorf("Expected (*)xSlice or xMap but got %v", u))
	}
	return nil
}
func convProtoOrNames(x xAny) []protoOrName {
	a := getSlice(x)
	list := make([]protoOrName, len(a))
	for i, x := range a {
		list[i] = convProtoOrName(x)
	}
	return list
}

func convprotoGroup(x xAny) *protoGroup {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*protoGroup)
	}
	p := new(protoGroup)
	m["ref"] = p
	p.name = getString(m["name"])
	p.isUsed = getBool(m["is_used"])
	if p.isUsed {
		p.elements = convProtos(m["elements"])
	} else {
		p.pairs = convProtoOrNames(m["pairs"])
	}
	return p
}
func convprotoGroupMap(x xAny) map[string]*protoGroup {
	m := getMap(x)
	n := make(map[string]*protoGroup)
	for name, xGroup := range m {
		n[name] = convprotoGroup(xGroup)
	}
	return n
}

func convObjGroup(x xAny) *objGroup {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*objGroup)
	}
	g := new(objGroup)
	m["ref"] = g
	g.name = getString(m["name"])
	g.isUsed = getBool(m["is_used"])
	return g
}
func convObjGroupMap(x xAny) map[string]*objGroup {
	m := getMap(x)
	n := make(map[string]*objGroup)
	for name, xGroup := range m {
		n[name] = convObjGroup(xGroup)
	}
	return n
}

func convService(x xAny) *service {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*service)
	}
	s := new(service)
	m["ref"] = s
	s.name = getString(m["name"])
	s.disabled = getBool(m["disabled"])
	s.hasUnenforceable = getBool(m["has_unenforceable"])
	if list, ok := m["overlaps"]; ok {
		xOverlaps := list.(xSlice)
		overlaps := make([]*service, len(xOverlaps))
		for i, xOverlap := range xOverlaps {
			overlaps[i] = convService(xOverlap)
		}
		s.overlaps = overlaps
		s.overlapsUsed = make(map[*service]bool)
	}
	s.multiOwner = getBool(m["multi_owner"])
	s.subOwner = convOwner(m["sub_owner"])
	s.unknownOwner = getBool(m["unknown_owner"])
	s.user = convSrvObjects(m["user"])
	return s
}
func convServiceMap(x xAny) map[string]*service {
	m := getMap(x)
	n := make(map[string]*service)
	for name, xService := range m {
		n[name] = convService(xService)
	}
	return n
}

func convunexpRule(x xAny) *unexpRule {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*unexpRule)
	}
	r := new(unexpRule)
	m["ref"] = r
	r.hasUser = getString(m["has_user"])
	r.prt = convProtoOrNames(m["prt"])
	r.service = convService(m["service"])
	return r
}

func convAnyRule(x xAny) *groupedRule {
	s := convServiceRule(x)
	r := new(groupedRule)
	r.serviceRule = s
	r.src = []someObj{s.src[0].(*network)}
	r.dst = []someObj{s.dst[0].(*network)}
	return r
}

func convServiceRule(x xAny) *serviceRule {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*serviceRule)
	}
	r := new(serviceRule)
	m["ref"] = r

	r.deny = getBool(m["deny"])
	r.src = convSrvObjects(m["src"])
	r.dst = convSrvObjects(m["dst"])
	r.prt = convProtos(m["prt"])
	r.srcRange = convProto(m["src_range"])
	if log, ok := m["log"]; ok {
		r.log = getString(log)
	}
	r.srcNet = getBool(m["src_net"])
	r.dstNet = getBool(m["dst_net"])
	r.noCheckSupernetRules = getBool(m["no_check_supernet_rules"])
	r.reversed = getBool(m["reversed"])
	r.stateless = getBool(m["stateless"])
	r.statelessICMP = getBool(m["stateless_icmp"])
	r.oneway = getBool(m["oneway"])
	r.overlaps = getBool(m["overlaps"])
	r.rule = convunexpRule(m["rule"])
	return r
}

func convServiceRuleList(x xAny) []*serviceRule {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	rules := make([]*serviceRule, len(a))
	for i, x := range a {
		rules[i] = convServiceRule(x)
	}
	return rules
}

func convServiceRules(x xAny) *serviceRules {
	m := getMap(x)
	r := new(serviceRules)
	r.permit = convServiceRuleList(m["permit"])
	r.deny = convServiceRuleList(m["deny"])
	return r
}

func convRadiusAttributes(x xAny) map[string]string {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(map[string]string)
	}
	return getMapStringString(x)
}

func convCrypto(x xAny) *crypto {
	if x == nil {
		return nil
	}
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*crypto)
	}
	c := new(crypto)
	m["ref"] = c
	c.name = getString(m["name"])
	c.ipsec = convIpsec(m["type"])
	c.detailedCryptoAcl = getBool(m["detailed_crypto_acl"])
	c.tunnels = convNetworks(m["tunnels"])
	return c
}
func convCryptoList(x xAny) []*crypto {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	b := make([]*crypto, len(a))
	for i, x := range a {
		b[i] = convCrypto(x)
	}
	return b
}
func convCryptoMap(x xAny) map[string]*crypto {
	m := getMap(x)
	n := make(map[string]*crypto)
	for name, xCrypto := range m {
		n[name] = convCrypto(xCrypto)
	}
	return n
}

func convIpsec(x xAny) *ipsec {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*ipsec)
	}
	c := new(ipsec)
	m["ref"] = c
	c.name = getString(m["name"])
	c.isakmp = convIsakmp(m["key_exchange"])
	if list, ok := m["lifetime"]; ok {
		tryInt := func(x xAny) int {
			if x == nil {
				return -1
			}
			return getInt(x)
		}
		a := getSlice(list)
		c.lifetime = &[2]int{tryInt(a[0]), tryInt(a[1])}
	}
	c.ah = getString(m["ah"])
	c.espAuthentication = getString(m["esp_authentication"])
	c.espEncryption = getString(m["esp_encryption"])
	c.pfsGroup = getString(m["pfs_group"])
	return c
}

func convXXRP(x xAny) *xxrp {
	m := getMap(x)
	i := new(xxrp)
	i.prt = convProto(m["prt"])
	i.mcast = convMcastInfo(m)
	return i
}
func convXXRPInfo(x xAny) map[string]*xxrp {
	m := getMap(x)
	n := make(map[string]*xxrp)
	for k, v := range m {
		n[getString(k)] = convXXRP(v)
	}
	return n
}

func convIsakmp(x xAny) *isakmp {
	m := getMap(x)
	if o, ok := m["ref"]; ok {
		return o.(*isakmp)
	}
	c := new(isakmp)
	m["ref"] = c
	c.name = getString(m["name"])
	c.authentication = getString(m["authentication"])
	c.encryption = getString(m["encryption"])
	c.group = getString(m["group"])
	c.hash = getString(m["hash"])
	c.trustPoint = getString(m["trust_point"])
	c.ikeVersion = getInt(m["ike_version"])
	c.lifetime = getInt(m["lifetime"])
	c.natTraversal = getString(m["nat_traversal"])
	return c
}

func getTriState(x xAny) conf.TriState {
	var result conf.TriState
	result.Set(getString(x))
	return result
}

func convConfig(x xAny) *conf.Config {
	m := getMap(x)
	c := new(conf.Config)
	c.CheckDuplicateRules = getTriState(m["check_duplicate_rules"])
	c.CheckFullyRedundantRules = getTriState(m["check_fully_redundant_rules"])
	c.CheckPolicyDistributionPoint =
		getTriState(m["check_policy_distribution_point"])
	c.CheckRedundantRules = getTriState(m["check_redundant_rules"])
	c.CheckServiceUnknownOwner = getTriState(m["check_service_unknown_owner"])
	c.CheckServiceMultiOwner = getTriState(m["check_service_multi_owner"])
	c.CheckSubnets = getTriState(m["check_subnets"])
	c.CheckSupernetRules = getTriState(m["check_supernet_rules"])
	c.CheckTransientSupernetRules =
		getTriState(m["check_transient_supernet_rules"])
	c.CheckUnenforceable = getTriState(m["check_unenforceable"])
	c.CheckUnusedGroups = getTriState(m["check_unused_groups"])
	c.CheckUnusedOwners = getTriState(m["check_unused_owners"])
	c.CheckUnusedProtocols = getTriState(m["check_unused_protocols"])

	c.AutoDefaultRoute = getBool(m["auto_default_route"])
	c.IgnoreFiles = getRegexp(m["ignore_files"])
	c.IPV6 = getBool(m["ipv6"])
	c.MaxErrors = getInt(m["max_errors"])
	c.Verbose = getBool(m["verbose"])
	c.TimeStamps = getBool(m["time_stamps"])
	c.Pipe = getBool(m["pipe"])
	return c
}

func ImportFromPerl() {
	var bytes []byte
	var err error
	if len(os.Args) > 1 {
		name := os.Args[1]
		bytes, err = ioutil.ReadFile(name)
	} else {
		bytes, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		panic(err)
	}
	var m xMap
	err = sereal.Unmarshal(bytes, &m)
	if err != nil {
		panic(err)
	}
	conf.Conf = convConfig(m["config"])
	conf.StartTime = time.Unix(int64(m["start_time"].(int)), 0)
	diag.Progress("Importing from Perl")

	ascendingAreas = convAreas(m["ascending_areas"])
	cryptoMap = convCryptoMap(m["crypto"])
	denyAny6Rule = convAnyRule(m["deny_any6_rule"])
	denyAnyRule = convAnyRule(m["deny_any_rule"])
	InPath = getString(m["in_path"])
	managedRouters = convRouters(m["managed_routers"])
	NATDomains = convNATDomains(m["natdomains"])
	NATTag2natType = getMapStringString(m["nat_tag2nat_type"])
	network00 = convNetwork(m["network_00"])
	network00v6 = convNetwork(m["network_00_v6"])
	allNetworks = convNetworks(m["all_networks"])
	OutDir = getString(m["out_dir"])
	owners = convOwnerMap(m["owners"])
	permitAny6Rule = convAnyRule(m["permit_any6_rule"])
	permitAnyRule = convAnyRule(m["permit_any_rule"])
	program = getString(m["program"])
	groups = convObjGroupMap(m["groups"])
	protocolGroups = convprotoGroupMap(m["protocolgroups"])
	protocols = convProtoMap(m["protocols"])
	prtMap = convProtoLookup(m["prt_hash"])
	prtAh = convProto(m["prt_ah"])
	prtBootpc = convProto(m["prt_bootpc"])
	prtBootps = convProto(m["prt_bootps"])
	prtEsp = convProto(m["prt_esp"])
	prtIP = convProto(m["prt_ip"])
	prtIke = convProto(m["prt_ike"])
	prtNatt = convProto(m["prt_natt"])
	prtUDP = convProto(m["prt_udp"])
	rangeTCPEstablished = convProto(m["range_tcp_established"])
	routingOnlyRouters = convRouters(m["routing_only_routers"])
	sRules = convServiceRules(m["service_rules"])
	services = convServiceMap(m["services"])
	version = getString(m["version"])
	xxrpInfo = convXXRPInfo(m["xxrp_info"])
	zones = convZones(m["zones"])
}

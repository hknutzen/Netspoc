package pass1

import (
	"fmt"
	"github.com/Sereal/Sereal/Go/sereal"
	"io/ioutil"
	"net"
	"os"
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
	default:
		x.ip = net.IP(s)
	}
	if up, ok := m["up"]; ok {
		x.up = convSomeObj(up)
	}
}
func (x *netObj) setCommon(m xMap) {
	x.ipObj.setCommon(m)
	x.network = convNetwork(m["network"])
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
	n.interfaces = convRouterIntfs(m["interfaces"])
	n.zone = convZone(m["zone"])
	n.hasOtherSubnet = getBool(m["has_other_subnet"])
	n.maxSecondaryNet = convNetwork(m["max_secondary_net"])
	n.nat = convNetNat(m["nat"])
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
	n.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	return n
}
func convNetworks(x xAny) []*network {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	networks := make([]*network, len(a))
	for i, x := range a {
		networks[i] = convNetwork(x)
	}
	return networks
}

func convSubnet(x xAny) *subnet {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*subnet)
	}
	s := new(subnet)
	m["ref"] = s
	s.setCommon(m)
	s.mask = m["mask"].([]byte)
	s.nat = convIPNat(m["nat"])
	s.id = getString(m["id"])
	s.ldapId = getString(m["ldap_id"])
	s.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	return s
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
	d.CommentChar = getString(m["comment_char"])
	d.Class = getString(m["class"])
	d.crypto = getString(m["crypto"])
	d.DoAuth = getBool(m["do_auth"])
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
	r.needProtect = getBool(m["need_protect"])
	r.noGroupCode = getBool(m["no_group_code"])
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
	r.vrfMembers = convRouters(m["vrf_members"])
	r.origRouter = convRouter(m["orig_router"])
	r.radiusAttributes = convRadiusAttributes(m["radius_attributes"])
	r.toZone1 = convRouterIntf(m["to_zone1"])
	r.trustPoint = getString(m["trust_point"])
	r.ipV6 = getBool(m["ipv6"])
	r.vrf = getString(m["vrf"])
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
	i.loop = convLoop(m["loop"])
	i.loopback = getBool(m["loopback"])
	i.loopZoneBorder = getBool(m["loop_zone_border"])
	i.mainIntf = convRouterIntf(m["main_interface"])
	i.nat = convIPNat(m["nat"])
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
		n1 := make(map[*routerIntf]map[*network]bool)
		m2 := getMap(m["hopref2obj"])
		n2 := make(map[string]*routerIntf)
		for ref, intf := range m2 {
			n2[getString(ref)] = convRouterIntf(intf)
		}
		for ref, netMap := range m1 {
			m := getMap(netMap)
			n := make(map[*network]bool)
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
	return a
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
	z.loop = convLoop(m["loop"])
	z.natDomain = convNATDomain(m["nat_domain"])
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
	d.natSet = convNatSet(m["nat_set"])
	return d
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

func convService(x xAny) *service {
	m := getMap(x)
	if s, ok := m["ref"]; ok {
		return s.(*service)
	}
	s := new(service)
	m["ref"] = s
	s.name = getString(m["name"])
	s.disabled = getBool(m["disabled"])
	if list, ok := m["overlaps"]; ok {
		xOverlaps := list.(xSlice)
		overlaps := make([]*service, len(xOverlaps))
		for i, xOverlap := range xOverlaps {
			overlaps[i] = convService(xOverlap)
		}
		s.overlaps = overlaps
		s.overlapsUsed = make(map[*service]bool)
	}
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
	r.service = convService(m["service"])
	r.prt = convProtoOrNames(m["prt"])
	return r
}

func convRule(x xAny) *groupedRule {
	m := getMap(x)
	if r, ok := m["ref"]; ok {
		return r.(*groupedRule)
	}
	r := new(groupedRule)
	m["ref"] = r
	r.deny = getBool(m["deny"])
	r.src = convSomeObjects(m["src"])
	r.dst = convSomeObjects(m["dst"])
	r.prt = convProtos(m["prt"])
	r.srcRange = convProto(m["src_range"])
	r.srcPath = convPathStore(m["src_path"])
	r.dstPath = convPathStore(m["dst_path"])
	if log, ok := m["log"]; ok {
		r.log = getString(log)
	}
	r.stateless = getBool(m["stateless"])
	r.statelessICMP = getBool(m["stateless_icmp"])
	r.overlaps = getBool(m["overlaps"])
	r.rule = convunexpRule(m["rule"])
	r.someNonSecondary = getBool(m["some_non_secondary"])
	r.somePrimary = getBool(m["some_primary"])
	return r
}

func convRules(x xAny) []*groupedRule {
	if x == nil {
		return nil
	}
	a := getSlice(x)
	rules := make([]*groupedRule, len(a))
	for i, x := range a {
		rules[i] = convRule(x)
	}
	return rules
}

func convpathRules(x xAny) *pathRules {
	m := getMap(x)
	r := new(pathRules)
	r.permit = convRules(m["permit"])
	r.deny = convRules(m["deny"])
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
	c.ipsec = convIpsec(m["type"])
	c.detailedCryptoAcl = getBool(m["detailed_crypto_acl"])
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
	return c
}

func convConfig(x xAny) Config {
	m := getMap(x)
	c := Config{
		Verbose:                  getBool(m["verbose"]),
		TimeStamps:               getBool(m["time_stamps"]),
		Pipe:                     getBool(m["pipe"]),
		MaxErrors:                getInt(m["max_errors"]),
		CheckDuplicateRules:      getString(m["check_duplicate_rules"]),
		CheckRedundantRules:      getString(m["check_redundant_rules"]),
		CheckFullyRedundantRules: getString(m["check_fully_redundant_rules"]),
		autoDefaultRoute:         getBool(m["auto_default_route"]),
	}
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
	config = convConfig(m["config"])
	startTime = time.Unix(int64(m["start_time"].(int)), 0)
	progress("Importing from Perl")

	denyAny6Rule = convRule(m["deny_any6_rule"])
	denyAnyRule = convRule(m["deny_any_rule"])
	managedRouters = convRouters(m["managed_routers"])
	network00 = convNetwork(m["network_00"])
	network00v6 = convNetwork(m["network_00_v6"])
	outDir = getString(m["out_dir"])
	pRules = convpathRules(m["path_rules"])
	permitAny6Rule = convRule(m["permit_any6_rule"])
	permitAnyRule = convRule(m["permit_any_rule"])
	program = getString(m["program"])
	protocolgroups = convprotoGroupMap(m["protocolgroups"])
	protocols = convProtoMap(m["protocols"])
	prtBootpc = convProto(m["prt_bootpc"])
	prtBootps = convProto(m["prt_bootps"])
	prtIP = convProto(m["prt_ip"])
	routingOnlyRouters = convRouters(m["routing_only_routers"])
	services = convServiceMap(m["services"])
	version = getString(m["version"])
	xxrpInfo = convXXRPInfo(m["xxrp_info"])
	zones = convZones(m["zones"])
}

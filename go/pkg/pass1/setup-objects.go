package pass1

import (
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var symTable *symbolTable

func ReadNetspoc(path string) {
	toplevel := parseFiles(path)
	setupTopology(toplevel)
}

func ShowReadStatistics() {
	r := len(symTable.router) + len(symTable.router6)
	n := len(symTable.network)
	h := len(symTable.host)
	s := len(symTable.service)
	diag.Info("Read: %d routers, %d networks, %d hosts, %d services", r, n, h, s)
}

func parseFiles(path string) []ast.Toplevel {
	var result []ast.Toplevel
	process := func(input *filetree.Context) {
		source := []byte(input.Data)
		nodes := parser.ParseFile(source, input.Path)
		if input.IPV6 {
			for _, n := range nodes {
				n.SetIPV6()
			}
		}
		result = append(result, nodes...)
	}
	filetree.Walk(path, process)
	return result
}

func setupTopology(toplevel []ast.Toplevel) {
	checkDuplicate(toplevel)
	sym := createSymbolTable()
	prtMap = initPrtMap()
	initStdProtocols(sym)
	symTable = sym
	setupObjects(toplevel, sym)
	AbortOnError()
	services = sym.service
	linkTunnels(sym)
	linkVirtualInterfaces()
	splitSemiManagedRouter()
}

type symbolTable struct {
	// Leaf nodes, referencing nothing.
	isakmp map[string]*isakmp
	owner  map[string]*owner
	// Named protocols
	protocol map[string]*proto
	// Unnamed protocols like "tcp 80"
	unnamedProto map[string]*proto
	// References protocolgroup, protocol
	protocolgroup map[string]*protoGroup
	// References network, owner
	network   map[string]*network
	aggregate map[string]*network
	// References owner
	host map[string]*host
	// References host, owner, protocolgroup+
	router  map[string]*router
	router6 map[string]*router
	// References network, owner, crypto, routerIntf(via crypto)
	routerIntf map[string]*routerIntf
	// References interface, group+, owner
	area map[string]*area
	// References group+, protocolgroup+, owner, service
	service map[string]*service
	// References host, network, interface, area, aggregate, group
	group map[string]*objGroup
	// References interface, group+
	pathrestriction map[string]*ast.TopList
	// References isakmp
	ipsec map[string]*ipsec
	// References ipsec
	crypto map[string]*crypto
}

func createSymbolTable() *symbolTable {
	s := new(symbolTable)
	s.network = make(map[string]*network)
	s.host = make(map[string]*host)
	s.router = make(map[string]*router)
	s.router6 = make(map[string]*router)
	s.routerIntf = make(map[string]*routerIntf)
	s.area = make(map[string]*area)
	s.service = make(map[string]*service)
	s.protocol = make(map[string]*proto)
	s.unnamedProto = make(map[string]*proto)
	s.protocolgroup = make(map[string]*protoGroup)
	s.group = make(map[string]*objGroup)
	s.pathrestriction = make(map[string]*ast.TopList)
	s.aggregate = make(map[string]*network)
	s.owner = make(map[string]*owner)
	s.crypto = make(map[string]*crypto)
	s.ipsec = make(map[string]*ipsec)
	s.isakmp = make(map[string]*isakmp)
	return s
}

func initPrtMap() *protoLookup {
	m := new(protoLookup)
	m.icmp = make(map[string]*proto)
	m.tcp = make(map[string]*proto)
	m.udp = make(map[string]*proto)
	m.proto = make(map[string]*proto)
	return m
}

func setupObjects(l []ast.Toplevel, s *symbolTable) {
	var ipsec []*ast.TopStruct
	var crypto []*ast.TopStruct
	var networks []*ast.Network
	var aggregates []*ast.TopStruct
	var routers []*ast.Router
	var areas []*ast.Area
	var pathrestrictions []*ast.TopList
	var services []*ast.Service
	for _, a := range l {
		typ, name := splitTypedName(a.GetName())
		switch a.(type) {
		case *ast.Network, *ast.Router:
		default:
			if !isSimpleName(name) {
				errMsg("Invalid identifier in definition of '%s.%s'", typ, name)
			}
		}
		switch x := a.(type) {
		case *ast.Protocol:
			setupProtocol(x, s)
		case *ast.Protocolgroup:
			l := make(stringList, 0, len(x.ValueList))
			for _, v := range x.ValueList {
				l.push(v.Value)
			}
			s.protocolgroup[name] = &protoGroup{name: a.GetName(), list: l}
		case *ast.Network:
			s.network[name] = new(network)
			networks = append(networks, x)
		case *ast.Router:
			routers = append(routers, x)
		case *ast.Area:
			areas = append(areas, x)
		case *ast.Service:
			s.service[name] = new(service)
			services = append(services, x)
		case *ast.TopStruct:
			switch typ {
			case "owner":
				setupOwner(x, s)
			case "isakmp":
				setupIsakmp(x, s)
			case "ipsec":
				ipsec = append(ipsec, x)
			case "crypto":
				crypto = append(crypto, x)
			case "any":
				aggregates = append(aggregates, x)
			}
		case *ast.TopList:
			switch typ {
			case "group":
				g := &objGroup{name: x.Name, elements: x.Elements}
				g.ipV6 = x.IPV6
				s.group[name] = g
			case "pathrestriction":
				pathrestrictions = append(pathrestrictions, x)
			}
		}
	}
	for _, a := range ipsec {
		setupIpsec(a, s)
	}
	for _, a := range crypto {
		setupCrypto(a, s)
	}
	for _, a := range networks {
		setupNetwork(a, s)
	}
	for _, a := range aggregates {
		setupAggregate(a, s)
	}
	for _, a := range routers {
		setupRouter(a, s)
	}
	for _, a := range areas {
		setupArea(a, s)
	}
	for _, a := range pathrestrictions {
		setupPathrestriction(a, s)
	}
	for _, a := range services {
		setupService(a, s)
	}
}

func setupProtocol(a *ast.Protocol, s *symbolTable) {
	name := a.Name
	v := a.Value
	l := strings.Split(v, ", ")
	def := l[0]
	mod := l[1:]
	p := getSimpleProtocol(def, a.IPV6, name)
	p.name = name
	pName := name[len("protocol:"):]
	s.protocol[pName] = p
	addProtocolModifiers(mod, p)
}

func getSimpleProtocol(def string, v6 bool, ctx string) *proto {
	p := new(proto)
	p.name = def
	l := strings.Split(def, " ")
	proto := l[0]
	nums := l[1:]
	p.proto = proto
	switch proto {
	case "ip":
		if len(nums) != 0 {
			errMsg("Unexpected details after %s", ctx)
		}
	case "tcp", "udp":
		addPortRanges(nums, p, ctx)
	case "icmpv6":
		p.proto = "icmp"
		addICMPTypeCode(nums, p, ctx)
		if !v6 {
			errMsg("Must not be used with IPv4: %s", ctx)
		}
	case "icmp":
		addICMPTypeCode(nums, p, ctx)
		if v6 {
			errMsg("Must not be used with IPv6: %s", ctx)
		}
	case "proto":
		addProtoNr(nums, p, v6, ctx)
	default:
		errMsg("Unknown protocol in %s", ctx)
		p.proto = "ip"
	}
	return p
}

func addPortRanges(nums []string, p *proto, ctx string) {
	switch len(nums) {
	case 0:
		p.dst = getRangeProto(1, 65535, p)
	case 1:
		p.dst = getRange1(nums[0], p, ctx)
	case 3:
		if nums[1] == "-" {
			p.dst = getRange(nums[0], nums[2], p, ctx)
		} else if nums[1] == ":" {
			p.src = getRange1(nums[0], p, ctx)
			p.dst = getRange1(nums[2], p, ctx)
		} else {
			errMsg("Invalid port range in %s", ctx)
		}
	case 5:
		if nums[1] == ":" && nums[3] == "-" {
			p.src = getRange1(nums[0], p, ctx)
			p.dst = getRange(nums[2], nums[4], p, ctx)
		} else if nums[1] == "-" && nums[3] == ":" {
			p.src = getRange(nums[0], nums[2], p, ctx)
			p.dst = getRange1(nums[4], p, ctx)
		} else {
			errMsg("Invalid port range in %s", ctx)
		}
	case 7:
		if nums[1] == "-" && nums[3] == ":" && nums[5] == "-" {
			p.src = getRange(nums[0], nums[2], p, ctx)
			p.dst = getRange(nums[4], nums[6], p, ctx)
		} else {
			errMsg("Invalid port range in %s", ctx)
		}
	default:
		errMsg("Invalid port range in %s", ctx)
	}
}

func getRange(s1, s2 string, p *proto, ctx string) *proto {
	n1 := getPort(s1, ctx)
	n2 := getPort(s2, ctx)
	if n1 > n2 {
		errMsg("Invalid port range in %s", ctx)
	}
	return getRangeProto(n1, n2, p)
}

func getRange1(s1 string, p *proto, ctx string) *proto {
	n1 := getPort(s1, ctx)
	return getRangeProto(n1, n1, p)
}

func getRangeProto(n1, n2 int, p *proto) *proto {
	key := strconv.Itoa(n1) + ":" + strconv.Itoa(n2)
	var m map[string]*proto
	if p.proto == "tcp" {
		m = prtMap.tcp
	} else {
		m = prtMap.udp
	}
	if p, found := m[key]; found {
		return p
	}
	p = &proto{name: p.name, proto: p.proto, ports: [2]int{n1, n2}}
	m[key] = p
	return p
}

func getPort(s, ctx string) int {
	num, err := strconv.Atoi(s)
	if err != nil {
		errMsg("Expected number in %s: %s", ctx, s)
		return 0
	}
	if num <= 0 {
		errMsg("Expected port number > 0 in %s", ctx)
	} else if num >= 65536 {
		errMsg("Expected port number < 65536 in %s", ctx)
	}
	return num
}

func addICMPTypeCode(nums []string, p *proto, ctx string) {
	p.icmpType = -1
	p.icmpCode = -1
	switch len(nums) {
	case 0:
		return
	case 3:
		if nums[1] != "/" {
			errMsg("Expected [TYPE [ / CODE]] in %s", ctx)
			break
		}
		p.icmpCode = getNum256(nums[2], ctx)
		fallthrough
	case 1:
		typ := getNum256(nums[0], ctx)
		p.icmpType = typ
		if typ == 0 || typ == 3 || typ == 11 {
			p.statelessICMP = true
		}
	default:
		errMsg("Expected [TYPE [ / CODE]] in %s", ctx)
	}
}

func addProtoNr(nums []string, p *proto, v6 bool, ctx string) {
	if len(nums) != 1 {
		errMsg("Expected single protocol number in %s", ctx)
		return
	}
	s := nums[0]
	switch getNum256(s, ctx) {
	case 0:
		errMsg("Invalid protocol number '0' in %s", ctx)
	case 1:
		if !v6 {
			errMsg("Must not use 'proto 1', use 'icmp' instead in %s", ctx)
			return
		}
	case 4:
		errMsg("Must not use 'proto 4', use 'tcp' instead in %s", ctx)
		return
	case 17:
		errMsg("Must not use 'proto 17', use 'udp' instead in %s", ctx)
		return
	case 58:
		if v6 {
			errMsg("Must not use 'proto 58', use 'icmpv6' instead in %s", ctx)
			return
		}
	}
	p.proto = s
}

func getNum256(s, ctx string) int {
	num, err := strconv.Atoi(s)
	if err != nil {
		errMsg("Expected number in %s: %s", ctx, s)
		return -1
	}
	if num < 0 {
		errMsg("Expected positive number in %s", ctx)
	} else if num >= 256 {
		errMsg("Expected number < 256 in %s", ctx)
	}
	return num
}

func addProtocolModifiers(l []string, p *proto) {
	if len(l) == 0 {
		return
	}
	m := new(modifiers)
	for _, s := range l {
		switch s {
		case "reversed":
			m.reversed = true
		case "stateless":
			m.stateless = true
		case "oneway":
			m.oneway = true
		case "src_net":
			m.srcNet = true
		case "dst_net":
			m.dstNet = true
		case "overlaps":
			m.overlaps = true
		case "no_check_supernet_rules":
			m.noCheckSupernetRules = true
		default:
			errMsg("Unknown modifier '%s' in %s", s, p.name)
		}
	}
	p.modifiers = m
}

func setupOwner(v *ast.TopStruct, s *symbolTable) {
	name := v.Name
	o := new(owner)
	o.name = name
	oName := name[len("owner:"):]
	s.owner[oName] = o
	for _, a := range v.Attributes {
		switch a.Name {
		case "admins":
			o.admins = getEmailList(a, name)
		case "watchers":
			o.watchers = getEmailList(a, name)
		case "show_all":
			o.showAll = getFlag(a, name)
			o.showHiddenOwners = true
		case "only_watch":
			o.onlyWatch = getFlag(a, name)
		case "hide_from_outer_owners":
			o.hideFromOuterOwners = getFlag(a, name)
		case "show_hidden_owners":
			o.showHiddenOwners = getFlag(a, name)
		default:
			errMsg("Unexpected attribute in %s: %s", name, a.Name)
		}
	}
	checkDuplAttr(v.Attributes, name)
	removeDupl(append(o.admins, o.watchers...), "admins/watchers of "+name)
}

type attrDescr struct {
	values   []string
	mapEmpty string
}

var isakmpAttr = map[string]attrDescr{
	"nat_traversal": attrDescr{
		values:   []string{"on", "additional", "off"},
		mapEmpty: "off",
	},
	"authentication": {
		values: []string{"preshare", "rsasig"},
	},
	"encryption": {
		values: []string{"aes", "aes192", "aes256", "des", "3des"},
	},
	"hash": {
		values: []string{"md5", "sha", "sha256", "sha384", "sha512"},
	},
	"ike_version": {
		values: []string{"1", "2"},
	},
	"group": {
		values: []string{"1", "2", "5", "14", "15", "16", "19", "20", "21", "24"},
	},
	"trust_point": {
		mapEmpty: "none",
	},
}

func setupIsakmp(v *ast.TopStruct, s *symbolTable) {
	name := v.Name
	is := new(isakmp)
	is.name = name
	isName := name[len("isakmp:"):]
	s.isakmp[isName] = is
	hasLifetime := false
	ikeVersion := ""
	for _, a := range v.Attributes {
		switch a.Name {
		case "nat_traversal":
			is.natTraversal = getAttr(a, isakmpAttr, name)
		case "authentication":
			is.authentication = getAttr(a, isakmpAttr, name)
		case "encryption":
			is.encryption = getAttr(a, isakmpAttr, name)
		case "hash":
			is.hash = getAttr(a, isakmpAttr, name)
		case "ike_version":
			ikeVersion = getAttr(a, isakmpAttr, name)
		case "lifetime":
			is.lifetime = getTimeVal(a, name)
			hasLifetime = true
		case "group":
			is.group = getAttr(a, isakmpAttr, name)
		case "trust_point":
			is.trustPoint = getAttr(a, isakmpAttr, name)
		default:
			errMsg("Unexpected attribute in %s: %s", name, a.Name)
		}
	}
	if ikeVersion == "" {
		is.ikeVersion = 1
	} else {
		is.ikeVersion, _ = strconv.Atoi(ikeVersion)
	}
	if is.authentication == "" {
		errMsg("Missing 'authentication' for %s", name)
	}
	if is.encryption == "" {
		errMsg("Missing 'encryption' for %s", name)
	}
	if is.hash == "" {
		errMsg("Missing 'hash' for %s", name)
	}
	if is.group == "" {
		errMsg("Missing 'group' for %s", name)
	}
	if !hasLifetime {
		errMsg("Missing 'lifetime' for %s", name)
	}
	checkDuplAttr(v.Attributes, name)
}

func getAttr(a *ast.Attribute, descr map[string]attrDescr, ctx string) string {
	v := getSingleValue(a, ctx)
	d := descr[a.Name]
	if l := d.values; l != nil {
		valid := false
		for _, v2 := range l {
			if v == v2 {
				valid = true
				break
			}
		}
		if !valid {
			errMsg("Invalid value in '%s' of %s: %s", a.Name, ctx, v)
		}
	}
	if v2 := d.mapEmpty; v2 != "" && v == v2 {
		v = ""
	}
	return v
}

var ipsecAttr = map[string]attrDescr{
	"esp_encryption": {
		values: []string{"none", "aes", "aes192", "aes256", "des", "3des"},
	},
	"esp_authentication": {
		values: []string{"none", "md5", "sha", "sha256", "sha384", "sha512"},
	},
	"ah": {
		values: []string{"none", "md5", "sha", "sha256", "sha384", "sha512"},
	},
	"pfs_group": {
		values: []string{"1", "2", "5", "14", "15", "16", "19", "20", "21", "24"},
	},
}

func setupIpsec(v *ast.TopStruct, s *symbolTable) {
	name := v.Name
	is := new(ipsec)
	is.name = name
	isName := name[len("ipsec:"):]
	s.ipsec[isName] = is
	for _, a := range v.Attributes {
		switch a.Name {
		case "key_exchange":
			is.isakmp = getIsakmpRef(a, s, name)
		case "esp_encryption":
			is.espEncryption = getAttr(a, ipsecAttr, name)
		case "esp_authentication":
			is.espAuthentication = getAttr(a, ipsecAttr, name)
		case "ah":
			is.ah = getAttr(a, ipsecAttr, name)
		case "pfs_group":
			is.pfsGroup = getAttr(a, ipsecAttr, name)
		case "lifetime":
			is.lifetime = getTimeKilobytesPair(a, name)
		default:
			errMsg("Unexpected attribute in %s: %s", name, a.Name)
		}
	}
	checkDuplAttr(v.Attributes, name)
	if is.lifetime == nil {
		errMsg("Missing 'lifetime' for %s", name)
	}
	if is.isakmp == nil {
		errMsg("Missing 'key_exchange' for %s", name)
	}
}

func setupCrypto(v *ast.TopStruct, s *symbolTable) {
	name := v.Name
	cr := new(crypto)
	cr.name = name
	crName := name[len("crypto:"):]
	s.crypto[crName] = cr
	for _, a := range v.Attributes {
		switch a.Name {
		case "detailed_crypto_acl":
			cr.detailedCryptoAcl = getFlag(a, name)
		case "type":
			cr.ipsec = getIpsecRef(a, s, name)
		default:
			errMsg("Unexpected attribute in %s: %s", name, a.Name)
		}
	}
	checkDuplAttr(v.Attributes, name)
	if cr.ipsec == nil {
		errMsg("Missing 'type' for %s", name)
	}
}

func setupNetwork(v *ast.Network, s *symbolTable) {
	name := v.Name
	netName := name[len("network:"):]
	n := s.network[netName]
	n.name = name
	n.ipV6 = v.IPV6
	i := strings.Index(netName, "/")
	if i != -1 {
		n.bridged = true
	}
	if i != -1 && !isSimpleName(netName[:i]) || !isSimpleName(netName[i+1:]) {
		errMsg("Invalid identifier in definition of '%s'", name)
	}
	var ldapAppend string
	hasIP := false
	for _, a := range v.Attributes {
		switch a.Name {
		case "ip":
			n.ip, n.mask = getIpPrefix(a, v.IPV6, name)
			hasIP = true
		case "unnumbered":
			n.unnumbered = getFlag(a, name)
		case "has_subnets":
			n.hasSubnets = getFlag(a, name)
		case "crosslink":
			n.crosslink = getFlag(a, name)
		case "subnet_of":
			n.subnetOf = tryNetworkRef(a, s, n.ipV6, name)
		case "owner":
			n.owner = getRealOwnerRef(a, s, name)
		case "cert_id":
			n.certId = getSingleValue(a, name)
		case "ldap_append":
			ldapAppend = getSingleValue(a, name)
		case "radius_attributes":
			n.radiusAttributes = getRadiusAttributes(a, name)
		case "partition":
			n.partition = getIdentifier(a, name)
		case "overlaps", "unknown_owner", "multi_owner", "has_unenforceable":
			n.attr = addAttr(a, n.attr, name)
		default:
			if nat := addNetNat(a, n.nat, v.IPV6, s, name); nat != nil {
				n.nat = nat
			} else {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}
	checkDuplAttr(v.Attributes, name)
	for _, a := range v.Hosts {
		h := setupHost(a, s, n)
		if h.ldapId != "" {
			h.ldapId += ldapAppend
		}
	}

	// Unnumbered network must not have any other attributes.
	if n.unnumbered {
		for _, a := range v.Attributes {
			switch a.Name {
			case "crosslink", "unnumbered":
			default:
				if strings.HasPrefix("nat:", a.Name) {
					errMsg("Unnumbered %s must not have NAT definition", name)
				} else {
					errMsg("Unnumbered %s must not have attribute '%s'",
						name, a.Name)
				}
			}
		}
		if n.bridged {
			errMsg("Unnumbered %s must not be bridged", name)
		}
		if len(n.hosts) != 0 {
			errMsg("Unnumbered %s must not have host definition", name)
		}
	} else if n.bridged {
		for _, h := range n.hosts {
			if h.ipRange[0] != nil {
				errMsg("Bridged %s must not have %s with range (not implemented)",
					name, h.name)
			}
		}
		for _, nat := range n.nat {
			if !nat.identity {
				errMsg("Only identity NAT allowed for bridged %s", n.name)
				break
			}
		}
	} else if n.ip == nil && !hasIP {
		errMsg("Missing IP address for %s", name)
	} else {
		ip := n.ip
		mask := n.mask
		for _, h := range n.hosts {

			// Check compatibility of host IP and network IP/mask.
			if h.ip != nil {
				if !matchIp(h.ip, ip, mask) {
					errMsg("IP of %s doesn't match IP/mask of %s", h.name, name)
				}
			} else {
				// Check range.
				if !(matchIp(h.ipRange[0], ip, mask) &&
					matchIp(h.ipRange[1], ip, mask)) {
					errMsg("IP range of %s doesn't match IP/mask of %s",
						h.name, name)
				}
			}

			// Compatibility of host and network NAT will be checked later,
			// after inherited NAT definitions have been processed.
		}
		if n.hosts != nil && n.crosslink {
			errMsg("Crosslink %s must not have host definitions", name)
		}

		// Check NAT definitions.
		for tag, nat := range n.nat {
			if !nat.dynamic {
				if bytes.Compare(nat.mask, mask) != 0 {
					errMsg("Mask for non dynamic nat:%s must be equal to mask of %s",
						tag, name)
				}
			}
		}

		// Check and mark networks with ID-hosts.
		ldapCount := 0
		idHostsCount := 0
		for _, h := range n.hosts {
			if h.ldapId != "" {
				ldapCount++
				h.id = h.ldapId
			} else if h.id != "" {
				idHostsCount++
			}
		}
		if ldapCount > 0 {

			// If one host has ldap_id, all hosts must have ldap_id.
			if len(n.hosts) != ldapCount {
				errMsg("All hosts must have attribute 'ldap_id' in %s", name)
			}
			if n.certId == "" {
				errMsg("Missing attribute 'cert_id' at %s having hosts"+
					" with attribute 'ldap_id'", name)
			} else if !isDomain(n.certId) {
				errMsg("Domain name expected in attribute 'cert_id' of %s", name)
			}

			// Mark network.
			n.hasIdHosts = true
		} else {
			if ldapAppend != "" {
				warnMsg("Ignoring 'ldap_append' at %s", name)
			}
			if n.certId != "" {
				n.certId = ""
				warnMsg("Ignoring 'cert_id' at %s", name)
			}
			if idHostsCount > 0 {

				// If one host has ID, all hosts must have ID.
				if len(n.hosts) != idHostsCount {
					errMsg("All hosts must have ID in %s", name)
				}

				// Mark network.
				n.hasIdHosts = true
			}
		}

		if !n.hasIdHosts && n.radiusAttributes != nil {
			warnMsg("Ignoring 'radius_attributes' at %s", name)
		}
	}
}

func setupHost(v *ast.Attribute, s *symbolTable, n *network) *host {
	name := v.Name
	v6 := n.ipV6
	h := new(host)
	h.ipV6 = v6
	hName := name[len("host:"):]
	if strings.HasPrefix(hName, "id:") {
		id := hName[len("id:"):]
		if !isIdHostname(id) {
			errMsg("Invalid name in definition of '%s'", name)
		}
		h.id = id
		nName := n.name[len("network:"):]
		hName += "." + nName
		name += "." + nName
	} else {
		if !isSimpleName(hName) {
			errMsg("Invalid identifier in definition of '%s'", name)
		}
	}
	h.name = name
	s.host[hName] = h
	h.network = n
	n.hosts = append(n.hosts, h)

	l := getComplexValue(v, "")
	for _, a := range l {
		switch a.Name {
		case "ip":
			h.ip = getIp(a, v6, name)
		case "range":
			h.ipRange = getIpRange(a, v6, name)
		case "owner":
			h.owner = getRealOwnerRef(a, s, name)
		case "ldap_id":
			h.ldapId = getSingleValue(a, name)
		case "radius_attributes":
			h.radiusAttributes = getRadiusAttributes(a, name)
		default:
			if nat := addIPNat(a, h.nat, v6, name); nat != nil {
				h.nat = nat
			} else {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}
	if (h.ip == nil) == (h.ipRange[0] == nil) {
		errMsg("%s needs exactly one of attributes 'ip' and 'range'", name)
	}
	if h.id != "" {
		if h.ldapId != "" {
			warnMsg("Ignoring attribute 'ldap_id' at %s", name)
			h.ldapId = ""
		}
	} else if h.ldapId != "" {
		if h.ipRange[0] == nil {
			errMsg("Attribute 'ldap_Id' must only be used together with"+
				" IP range at %s", name)
		}
	} else if h.radiusAttributes != nil {
		warnMsg("Ignoring 'radius_attributes' at %s", name)
	}
	if h.nat != nil && h.ipRange[0] != nil {
		// Before changing this,
		// add consistency tests in convert_hosts.
		errMsg("No NAT supported for %s with 'range'", name)
	}
	return h
}

func setupAggregate(v *ast.TopStruct, s *symbolTable) {
	name := v.Name
	v6 := v.IPV6
	ag := new(network)
	ag.name = name
	ag.isAggregate = true
	ag.ipV6 = v6
	agName := name[len("any:"):]
	s.aggregate[agName] = ag
	hasLink := false
	for _, a := range v.Attributes {
		switch a.Name {
		case "ip":
			ag.ip, ag.mask = getIpPrefix(a, v.IPV6, name)
		case "link":
			hasLink = true
			ag.link = getNetworkRef(a, s, v6, name)
		case "no_check_supernet_rules":
			ag.noCheckSupernetRules = getFlag(a, name)
		case "owner":
			ag.owner = getRealOwnerRef(a, s, name)
		case "overlaps", "unknown_owner", "multi_owner", "has_unenforceable":
			ag.attr = addAttr(a, ag.attr, name)
		default:
			if nat := addNetNat(a, ag.nat, v.IPV6, s, name); nat != nil {
				ag.nat = nat
			} else {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}
	checkDuplAttr(v.Attributes, name)
	if !hasLink {
		errMsg("Attribute 'link' must be defined for %s", name)
	}
	if ag.link == nil {
		ag.disabled = true
	}
	if len(ag.ip) == 0 {
		ag.ip = getZeroIp(v6)
		ag.mask = getZeroMask(v6)
	}
	if size, _ := ag.mask.Size(); size != 0 {
		if ag.noCheckSupernetRules {
			errMsg("Must not use attribute 'no_check_supernet_rules'"+
				" if IP is set for %s", name)
		}
		if m := ag.attr; m != nil {
			for key, _ := range m {
				errMsg("Must not use attribute '%s' if IP is set for %s", key, name)
			}
		}
	}
}

func setupArea(v *ast.Area, s *symbolTable) {
	name := v.Name
	v6 := v.IPV6
	ar := new(area)
	ar.name = name
	ar.ipV6 = v6
	arName := name[len("area:"):]
	s.area[arName] = ar
	for _, a := range v.Attributes {
		switch a.Name {
		case "anchor":
			ar.anchor = getNetworkRef(a, s, v.IPV6, name)
		case "router_attributes":
			ar.routerAttributes = getRouterAttributes(a, s, ar)
		case "owner":
			o := tryOwnerRef(a, s, name)
			if o != nil && o.onlyWatch {
				ar.watchingOwner = o
			} else {
				ar.owner = o
			}
		case "overlaps", "unknown_owner", "multi_owner", "has_unenforceable":
			ar.attr = addAttr(a, ar.attr, name)
		default:
			if nat := addNetNat(a, ar.nat, v.IPV6, s, name); nat != nil {
				ar.nat = nat
			} else {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}
	checkDuplAttr(v.Attributes, name)
	expand := func(u *ast.NamedUnion, att string) intfList {
		if u == nil {
			return nil
		}
		ctx := "'" + att + "' of " + name
		l := expandGroup(u.Elements, ctx, v.IPV6, false)
		result := make(intfList, 0, len(l))
		for _, el := range l {
			intf, ok := el.(*routerIntf)
			if !ok {
				errMsg("Unexpected '%s' in %s", el, ctx)
			} else if intf.router.managed == "" {
				errMsg("Must not reference unmanaged %s in %s", intf.name, ctx)
			} else {
				// Reverse swapped main and virtual interface.
				if main := intf.mainIntf; main != nil {
					intf = main
				}
				result.push(intf)
			}
		}
		return result
	}
	ar.border = expand(v.Border, "border")
	ar.inclusiveBorder = expand(v.InclusiveBorder, "inclusive_border")
	if (len(ar.border) != 0 || len(ar.inclusiveBorder) != 0) &&
		ar.anchor != nil {
		errMsg("Attribute 'anchor' must not be defined together with"+
			" 'border' or 'inclusive_border' for %s", name)
	}
	if len(ar.border) == 0 && len(ar.inclusiveBorder) == 0 && ar.anchor == nil {
		errMsg("At least one of attributes 'border', 'inclusive_border'"+
			" or 'anchor' must be defined for %s", name)
	}
}

func setupPathrestriction(v *ast.TopList, s *symbolTable) {
	name := v.Name
	l := expandGroup(v.Elements, name, v.IPV6, false)
	elements := make(intfList, 0, len(l))
	for _, obj := range l {
		intf, ok := obj.(*routerIntf)
		if !ok {
			errMsg("%s must not reference %s", name, obj)
		} else if intf.mainIntf != nil {
			// Pathrestrictions must not be applied to secondary interfaces
			errMsg("%s must not reference secondary %s", name, obj)
		} else {
			elements.push(intf)
		}
	}
	switch len(elements) {
	case 0:
		warnMsg("Ignoring %s without elements", name)
	case 1:
		warnMsg("Ignoring %s with only %s", name, elements[0])
		elements = nil
	}
	if len(elements) == 0 {
		return
	}
	addPathrestriction(name, elements)
}

func setupRouter(v *ast.Router, s *symbolTable) {
	name := v.Name
	v6 := v.IPV6
	r := new(router)
	r.name = name
	r.ipV6 = v6
	rName := name[len("router:"):]
	if v6 {
		s.router6[rName] = r
	} else {
		s.router[rName] = r
	}
	i := strings.Index(rName, "@")
	if i != -1 {
		r.deviceName = rName[:i]
		r.vrf = rName[i+1:]
	} else {
		r.deviceName = rName
	}
	if i != -1 && !isSimpleName(rName[:i]) || !isSimpleName(rName[i+1:]) {
		errMsg("Invalid identifier in definition of '%s'", name)
	}
	noProtectSelf := false
	var routingDefault *routing
	for _, a := range v.Attributes {
		switch a.Name {
		case "managed":
			r.managed = getManaged(a, name)
		case "filter_only":
			r.filterOnly = getIpPrefixList(a, v6, name)
		case "model":
			r.model = getModel(a, name)
		case "no_group_code":
			r.noGroupCode = getFlag(a, name)
		case "no_protect_self":
			noProtectSelf = getFlag(a, name)
		case "log_deny":
			r.logDeny = getFlag(a, name)
		case "acl_use_real_ip":
			r.aclUseRealIp = getFlag(a, name)
		case "routing":
			routingDefault = getRouting(a, name)
		case "owner":
			r.owner = getRealOwnerRef(a, s, name)
		case "radius_attributes":
			r.radiusAttributes = getRadiusAttributes(a, name)
		case "policy_distribution_point":
			r.policyDistributionPoint = tryHostRef(a, s, v6, name)
		case "general_permit":
			r.generalPermit = getGeneralPermit(a, s, v6, name)
		default:
			if !addLog(a, r) {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}
	checkDuplAttr(v.Attributes, name)

	// Find bridged interfaces of this device and check
	// existence of corresponding layer3 device.
	var l3Map map[string]bool
	if r.managed != "" {
		l3Map = make(map[string]bool)

		// Search bridge interface having
		// 1. name "interface:network/part" and
		// 2. no IP address.
	BRIDGED:
		for _, a := range v.Interfaces {
			idx := strings.Index(a.Name, "/")
			if idx == -1 {
				continue
			}
			for _, a2 := range a.ComplexValue {
				switch a2.Name {
				case "ip", "unnumbered", "negotiated":
					break BRIDGED
				}
			}
			// Remember name of corresponding layer3 interface without "/part".
			l3Map[a.Name[:idx]] = true
		}
		if len(l3Map) != 0 {
			// Check existence of layer3 interface(s).
			seen := make(map[string]bool)
			for _, a := range v.Interfaces {
				if l3Map[a.Name] {
					seen[a.Name] = true
				}
			}
			for name2, _ := range l3Map {
				if !seen[name2] {
					errMsg(
						"Must define %s at %s for corresponding bridge interfaces",
						name2, name)
				}
			}
		}
	}

	// Create objects representing hardware interfaces.
	// All logical interfaces using the same hardware are linked
	// to the same hardware object.
	hwMap := make(map[string]*hardware)
	for _, a := range v.Interfaces {
		setupInterface(a, s, hwMap, l3Map, r)
	}

	if managed := r.managed; managed != "" {
		if r.model == nil {
			errMsg("Missing 'model' for managed %s", name)

			// Prevent further errors.
			r.model = &model{name: "unknown"}
		}

		// Router is semiManaged if only routes are generated.
		if managed == "routing_only" {
			r.semiManaged = true
			r.routingOnly = true
			r.managed = ""
		}

		if r.vrf != "" && !r.model.canVRF {
			errMsg("Must not use VRF at %s of model %s", name, r.model.name)
		}

		// Inherit attribute 'routing' to interfaces.
		if routingDefault != nil {
			inherited := false
			for _, intf := range r.interfaces {
				if intf.routing == nil &&
					!(intf.unnumbered || intf.bridged || intf.loopback) {

					intf.routing = routingDefault
					inherited = true
				}
			}
			if !inherited {
				warnMsg("Ignoring attribute 'routing' of %s", name)
			}
		}
	}

	// Check again after "managed=routing_only" has been removed.
	if managed := r.managed; managed != "" {

		// Add unique zone to each managed router.
		// This represents the router itself.
		r.zone = new(zone)

		if managed == "local" {
			if r.filterOnly == nil {
				errMsg("Missing attribute 'filter_only' for %s", name)
			}
			if r.model.hasIoACL {
				errMsg("Must not use 'managed = local' at %s of model %s",
					name, r.model.name)
			}
		} else if r.filterOnly != nil {
			warnMsg("Ignoring attribute 'filter_only' at %s", name)
		}
		if r.logDeny && !r.model.canLogDeny {
			errMsg("Must not use attribute 'log_deny' at %s of moel %s",
				name, r.model.name)
		}

		if m := r.log; m != nil {
			if knownMod := r.model.logModifiers; knownMod != nil {
				for name2, mod := range m {

					// "": simple unmodified 'log' statement.
					if mod == "" || knownMod[mod] != "" {
						continue
					}

					var valid stringList
					for k := range knownMod {
						valid.push(k)
					}
					sort.Strings(valid)
					what := fmt.Sprintf("'log:%s = %s' at %s of model %s",
						name2, mod, name, r.model.name)
					if valid != nil {
						errMsg("Invalid %s\n Expected one of: %s",
							what, strings.Join(valid, "|"))
					} else {
						errMsg("Unexpected %s\n Use 'log:%s;' only.",
							what, name2)
					}
				}

				// Store defining log tags in global known_log.
				collectLog(m)
			} else {
				var names stringList
				for k := range m {
					names.push(k)
				}
				sort.Strings(names)
				name2 := names[0]
				errMsg("Must not use attribute 'log:%s' at %s of model %s",
					name2, name, r.model.name)
			}
		}

		if noProtectSelf && !r.model.needProtect {
			errMsg("Must not use attribute 'no_protect_self' at %s of model %s",
				name, r.model.name)
		}
		if r.model.needProtect {
			r.needProtect = !noProtectSelf
		}

		// Detailed interface processing for managed routers.
		hasCrypto := false
		isCryptoHub := false
		hasBindNat := false
		for _, intf := range r.interfaces {
			if intf.hub != nil || intf.spoke != nil {
				hasCrypto = true
				if r.model.crypto == "" {
					errMsg("Crypto not supported for %s of model %s",
						name, r.model.name)
				}
			}
			if intf.hub != nil {
				isCryptoHub = true
			}
			if intf.bindNat != nil {
				hasBindNat = true
			}
			// Link bridged interfaces with corresponding layer3 device.
			// Used in findAutoInterfaces.
			if intf.bridged {
				layer3Name := intf.name[len("interface:"):]
				idx := strings.Index(layer3Name, "/")
				layer3Name = layer3Name[:idx]
				intf.layer3Intf = s.routerIntf[layer3Name]
			}
		}

		checkNoInAcl(r)

		if r.aclUseRealIp {
			if !hasBindNat {
				warnMsg("Ignoring attribute 'acl_use_real_ip' at %s,\n"+
					" because it has no interface with 'bind_nat'", name)
			}
			if !r.model.canACLUseRealIP {
				warnMsg("Ignoring attribute 'acl_use_real_ip' at %s of model %s",
					name, r.model.name)
			}
			if hasCrypto {
				errMsg("Must not use attribute 'acl_use_real_ip' at %s"+
					" having crypto interfaces", name)
			}
		}
		if r.managed == "local" {
			if hasBindNat {
				errMsg("Attribute 'bind_nat' is not allowed"+
					" at interface of %s with 'managed = local'", name)
			}
		}
		if r.model.doAuth {
			if !isCryptoHub {
				warnMsg("Attribute 'hub' needs to be defined"+
					" at some interface of %s of model %s", name, r.model.name)
			}
		} else {
			if r.radiusAttributes != nil {
				warnMsg("Ignoring 'radius_attributes' at %s", name)
			}
		}
	} else {
		// Unmanaged device.
		if r.owner != nil {
			warnMsg("Ignoring attribute 'owner' at unmanaged %s", name)
		}
	}

	var otherSpoke *routerIntf
	for _, intf := range r.interfaces {

		if cr := intf.spoke; cr != nil {
			if otherSpoke != nil {
				errMsg("Must not define crypto spoke at more than one interface:\n"+
					" - %s\n"+
					" - %s", otherSpoke, intf)
				continue
			}
			otherSpoke = intf
			// Create tunnel network.
			netName := "tunnel:" + rName
			tNet := new(network)
			tNet.name = "network:" + netName
			tNet.tunnel = true
			tNet.ipV6 = v6

			// Tunnel network will later be attached to crypto hub.
			cr.tunnels.push(tNet)

			// Create tunnel interface.
			iName := rName + "." + netName
			tIntf := new(routerIntf)
			tIntf.name = "interface:" + iName
			tIntf.tunnel = true
			tIntf.crypto = cr
			tIntf.router = r
			tIntf.network = tNet
			tIntf.realIntf = intf
			tIntf.routing = intf.routing
			tIntf.bindNat = intf.bindNat
			tIntf.id = intf.id
			tIntf.ipV6 = v6
			if r.managed != "" {
				hw := intf.hardware
				tIntf.hardware = hw
				hw.interfaces.push(tIntf)
			}
			r.interfaces.push(tIntf)
			tNet.interfaces.push(tIntf)
		}

		if (intf.spoke != nil || intf.hub != nil) && !intf.noCheck {
			moveLockedIntf(intf)
		}
	}
}

func setupInterface(v *ast.Attribute, s *symbolTable,
	hwMap map[string]*hardware, l3Map map[string]bool, r *router) {

	rName := r.name[len("router:"):]
	nName := v.Name[len("interface:"):]
	iName := rName + "." + nName
	name := "interface:" + iName
	v6 := r.ipV6
	intf := new(routerIntf)
	intf.name = name
	intf.ipV6 = v6
	var l []*ast.Attribute

	// Allow short form of interface definition.
	if !emptyAttr(v) {
		l = getComplexValue(v, r.name)
	}

	var secondaryList intfList
	var virtual *routerIntf
	var vip bool
	var hwName string
	var subnetOf *network
	var nat map[string]*network
	hasIP := false
	for _, a := range l {
		switch a.Name {
		case "ip":
			hasIP = true
			ipList := getIpList(a, v6, name)
			intf.ip = ipList[0]
			ipList = ipList[1:]

			// Build interface objects for secondary IP addresses.
			// These objects are named interface:router.name.2, ...
			counter := 2
			for _, ip := range ipList {
				suffix := "." + strconv.Itoa(counter)
				name := name + suffix
				intf := new(routerIntf)
				intf.name = name
				intf.ipV6 = v6
				intf.ip = ip
				secondaryList.push(intf)
				counter++
			}
		case "hardware":
			hwName = getSingleValue(a, name)
		case "owner":
			intf.owner = getRealOwnerRef(a, s, name)
		case "unnumbered":
			intf.unnumbered = getFlag(a, name)
		case "negotiated":
			intf.negotiated = getFlag(a, name)
		case "loopback":
			intf.loopback = getFlag(a, name)
		case "vip":
			vip = getFlag(a, name)
		case "no_in_acl":
			intf.noInAcl = getFlag(a, name)
		case "dhcp_server":
			intf.dhcpServer = getFlag(a, name)
		case "dhcp_client":
			intf.dhcpClient = getFlag(a, name)
		case "subnet_of":
			subnetOf = tryNetworkRef(a, s, v6, name)
		case "hub":
			intf.hub = getCryptoRefList(a, s, name)
		case "spoke":
			intf.spoke = getCryptoRef(a, s, name)
		case "id":
			intf.id = getUserID(a, name)
		case "virtual":
			virtual = getVirtual(a, v6, name)
		case "bind_nat":
			l := getIdentifierList(a, name)
			sort.Strings(l)
			// Remove duplicates.
			var seen string
			j := 0
			for _, tag := range l {
				if tag == seen {
					warnMsg("Duplicate %s in 'bind_nat' of %s", tag, name)
				} else {
					seen = tag
					l[j] = tag
					j++
				}
			}
			intf.bindNat = l[:j]
		case "routing":
			intf.routing = getRouting(a, name)
		case "reroute_permit":
			intf.reroutePermit = tryNetworkRefList(a, s, v6, name)
		case "disabled":
			intf.disabled = getFlag(a, name)
		case "no_check":
			intf.noCheck = getFlag(a, name)
		default:
			if m := addIntfNat(a, nat, v6, s, name); m != nil {
				nat = m
			} else if strings.HasPrefix(a.Name, "secondary:") {
				_, name2 := splitCheckTypedName(a.Name)
				intf := new(routerIntf)
				intf.name = name + "." + name2
				sCtx := a.Name + " of " + name
				l := getComplexValue(a, name)
				for _, a2 := range l {
					switch a2.Name {
					case "ip":
						intf.ip = getIp(a2, v6, sCtx)
					default:
						errMsg("Unexpected attribute in %s: %s", sCtx, a2.Name)
					}
				}
				if intf.ip == nil {
					errMsg("Missing IP in %s", sCtx)
					intf.short = true
				}
				secondaryList.push(intf)
			} else {
				errMsg("Unexpected attribute in %s: %s", name, a.Name)
			}
		}
	}

	if l3Map[v.Name] {
		intf.loopback = true
		intf.isLayer3 = true
		if r.model.class == "ASA" {
			if hwName != "device" {
				errMsg(
					"Layer3 %s must use 'hardware' named 'device' for model 'ASA'",
					intf)
			}
		}
		if !hasIP {
			errMsg("Layer3 %s must have IP address", intf)
			// Prevent further errors.
			intf.disabled = true
		}
		if secondaryList != nil || virtual != nil {
			errMsg("Layer3 %s must not have secondary or virtual IP", intf)
			secondaryList = nil
			virtual = nil
		}
	}

	// Interface at bridged network
	// - without IP is interface of bridge,
	// - with IP is interface of router.
	if !hasIP && strings.Index(iName, "/") != -1 && r.managed != "" {
		intf.bridged = true
	}

	// Swap virtual interface and main interface
	// or take virtual interface as main interface if no main IP available.
	// Subsequent code becomes simpler if virtual interface is main interface.
	if virtual != nil {
		if intf.unnumbered {
			errMsg("No virtual IP supported for unnumbered %s", name)
		} else if intf.negotiated {
			errMsg("No virtual IP supported for negotiated %s", name)
		} else if intf.bridged {
			errMsg("No virtual IP supported for bridged %s", name)
		}
		if intf.ip != nil {

			// Move main IP to secondary.
			secondary := new(routerIntf)
			secondary.name = intf.name
			secondary.ip = intf.ip
			secondaryList.push(secondary)

			// But we need the original main interface
			// when handling auto interfaces.
			intf.origMain = secondary
		}
		if nat != nil {
			errMsg("%s with virtual interface must not use attribute 'nat'",
				name)
		}
		if intf.hub != nil {
			errMsg("%s with virtual interface must not use attribute 'hub'",
				name)
		}
		if intf.spoke != nil {
			errMsg("%s with virtual interface must not use attribute 'spoke'",
				name)
		}
		intf.name = virtual.name
		intf.ip = virtual.ip
		intf.redundant = virtual.redundant
		intf.redundancyType = virtual.redundancyType
		intf.redundancyId = virtual.redundancyId
		virtualInterfaces.push(intf)
	} else if !hasIP && !intf.unnumbered && !intf.negotiated && !intf.bridged {
		intf.short = true
	}
	if nat != nil && !hasIP {
		errMsg("No NAT supported for %s without IP", name)
	}

	// Attribute 'vip' is an alias for 'loopback'.
	var typ string
	if vip {
		typ = "'vip'"
		intf.loopback = true
	} else if intf.loopback {
		typ = "loopback"
	}
	if intf.bridged {
		typ = "bridged"
		if intf.owner != nil {
			errMsg("Attribute 'owner' not supported for %s %s", typ, name)
		}
	}
	if (intf.loopback || intf.bridged) && !intf.isLayer3 {
		if secondaryList != nil {
			errMsg("Secondary or virtual IP not supported for %s %s", typ, name)
			secondaryList = nil
			intf.origMain = nil // From virtual interface
		}

		// Most attributes are invalid for loopback interface.
		if intf.noInAcl {
			errMsg("Attribute 'no_in_acl' not supported for %s %s", typ, name)
		}
		if intf.noCheck {
			errMsg("Attribute 'no_check' not supported for %s %s", typ, name)
		}
		if intf.id != "" {
			errMsg("Attribute 'id' not supported for %s %s", typ, name)
		}
		if intf.hub != nil {
			errMsg("Attribute 'hub' not supported for %s %s", typ, name)
		}
		if intf.spoke != nil {
			errMsg("Attribute 'spoke' not supported for %s %s", typ, name)
		}
		if intf.dhcpClient {
			errMsg("Attribute 'dhcp_client' not supported for %s %s", typ, name)
		}
		if intf.dhcpServer {
			errMsg("Attribute 'dhcp_server' not supported for %s %s", typ, name)
		}
		if intf.routing != nil {
			errMsg("Attribute 'routing' not supported for %s %s", typ, name)
		}
		if intf.reroutePermit != nil {
			errMsg("Attribute 'reroute_permit' not supported for %s %s", typ, name)
		}
		if intf.unnumbered {
			errMsg("Attribute 'unnumbered' not supported for %s %s", typ, name)
		} else if intf.negotiated {
			errMsg("Attribute 'negotiated' not supported for %s %s", typ, name)
		} else if intf.short {
			errMsg("%s %s must have IP address", typ, name)
		}
	}
	if subnetOf != nil && !intf.loopback {
		errMsg("Attribute 'subnet_of' must not be used at %s\n"+
			" It is only valid together with attribute 'loopback'", name)
	}
	if intf.spoke != nil {
		if secondaryList != nil {
			errMsg("%s with attribute 'spoke' must not have secondary interfaces",
				intf)
			secondaryList = nil
		}
		if intf.hub != nil {
			errMsg("%s with attribute 'spoke' must not have attribute 'hub'",
				intf)
		}
	} else if intf.id != "" {
		errMsg("Attribute 'id' is only valid with 'spoke' at %s", intf)
	}
	if intf.noCheck && (intf.hub == nil || !r.model.doAuth) {
		intf.noCheck = false
		warnMsg("Ignoring attribute 'no_check' at %s", intf)
	}
	if secondaryList != nil {
		if intf.negotiated || intf.short || intf.bridged {
			errMsg("%s without IP address must not have secondary address", intf)
			secondaryList = nil
		}
	}
	if r.managed != "" {

		// Managed router must not have short interface.
		if intf.short {
			errMsg("Short definition of %s not allowed", name)
		}

		// Interface of managed router needs to have a hardware name.
		if hwName == "" {
			errMsg("Missing 'hardware' for %s", name)

			// Prevent further errors.
			hwName = "unknown"
		}

		var hw *hardware
		if hw = hwMap[hwName]; hw != nil {
			// All logical interfaces of one hardware interface
			// need to use the same NAT binding,
			// because NAT operates on hardware, not on logic.
			if !bindNatEq(intf.bindNat, hw.bindNat) {
				errMsg("All logical interfaces of %s\n"+
					" at %s must use identical NAT binding", hwName, r.name)
			}
		} else {
			hw = &hardware{name: hwName, loopback: true}
			hwMap[hwName] = hw
			r.hardware = append(r.hardware, hw)
			hw.bindNat = intf.bindNat
		}
		// Hardware keeps attribute .loopback only if all
		// interfaces have attribute .loopback.
		if !intf.loopback {
			hw.loopback = false
		}

		// Remember, which logical interfaces are bound
		// to which hardware.
		hw.interfaces.push(intf)
		intf.hardware = hw
		for _, s := range secondaryList {
			s.hardware = hw
			hw.interfaces.push(s)
		}

		// Interface of managed router must not have individual owner,
		// because whole device is managed from one place.
		if intf.owner != nil {
			warnMsg("Ignoring attribute 'owner' at managed %s", intf.name)
			intf.owner = nil
		}

		// Attribute 'vip' only supported at unmanaged router.
		if vip {
			errMsg("Must not use attribute 'vip' at %s of managed router", name)
		}

		// Don't allow 'routing=manual' at single interface, because
		// approve would remove manual routes otherwise.
		// Approve only leaves routes unchanged, if Netspoc generates
		// no routes at all.
		if rt := intf.routing; rt != nil && rt.name == "manual" {
			warnMsg("'routing=manual' must only be applied to router, not to %s",
				intf.name)
		}

		if l := intf.hub; l != nil {
			if intf.unnumbered || intf.negotiated || intf.short || intf.bridged {
				errMsg("Crypto hub %s must have IP address", intf)
			}
			for _, c := range l {
				if c.hub != nil {
					errMsg("Must use 'hub = %s' exactly once, not at both\n"+
						" - %s\n"+
						" - %s", c.name, c.hub, intf)
				} else {
					c.hub = intf
				}
			}
		}
	} else {
		// Unmanaged device.
		if intf.bindNat != nil {
			r.semiManaged = true
		}
		if intf.reroutePermit != nil {
			intf.reroutePermit = nil
			warnMsg("Ignoring attribute 'reroute_permit' at unmanaged %s", intf)
		}
		if intf.hub != nil {
			warnMsg("Ignoring attribute 'hub' at unmanaged %s", intf)
			intf.hub = nil
		}
		// Unmanaged bridge would complicate generation of static routes.
		if intf.bridged {
			errMsg("Unmanaged %s must not be bridged", intf)
		}
	}

	for _, s := range secondaryList {
		s.mainIntf = intf
		s.bindNat = intf.bindNat
		s.routing = intf.routing
		s.disabled = intf.disabled
	}

	// Automatically create a network for loopback interface.
	if intf.loopback {
		var shortName string
		var fullName string

		// Special handling needed for virtual loopback interfaces.
		// The created network needs to be shared among a group of
		// interfaces.
		if intf.redundant {

			// Shared virtual loopback network gets name
			// 'virtual:netname'. Don't use standard name to prevent
			// network from getting referenced from rules.
			shortName = "virtual:" + nName
			fullName = "network:" + shortName
		} else {

			// Single loopback network needs not to get an unique name.
			// Take an invalid name 'router.loopback' to prevent name
			// clashes with real networks or other loopback networks.
			fullName = intf.name
			shortName = fullName[len("interface:"):]
		}
		var n *network
		if intf.redundant {
			n = s.network[shortName]
		}
		if n == nil {
			n = new(network)
			n.name = fullName
			n.ip = intf.ip
			n.mask = getHostMask(v6)

			// Mark as automatically created.
			n.loopback = true
			n.subnetOf = subnetOf
			n.isLayer3 = intf.isLayer3
			n.ipV6 = v6

			// Move NAT definition to loopback network.
			n.nat = nat

			if intf.redundant {
				s.network[shortName] = n
			}
		}
		intf.network = n
		n.interfaces.push(intf)
	} else {
		// Link interface with network.
		n := s.network[nName]
		if n == nil {
			msg := "Referencing undefined network:%s from %s"
			if intf.disabled {
				warnMsg(msg, nName, name)
			} else {
				errMsg(msg, nName, name)
				intf.disabled = true
			}
		} else {
			for _, intf := range append(intfList{intf}, secondaryList...) {
				intf.network = n
				n.interfaces.push(intf)
				if !intf.short && !(hasIP && intf.ip == nil) {
					checkInterfaceIp(intf, n)
				}
			}
		}

		// Non loopback interface must use simple NAT with single IP
		// and without any NAT attributes.
		if len(nat) != 0 {
			intf.nat = make(map[string]net.IP)
			for tag, info := range nat {
				// Reject all non IP NAT attributes.
				if info.hidden || info.identity || info.dynamic {
					errMsg("Only 'ip' allowed in nat:%s of %s", tag, intf)
				} else {
					intf.nat[tag] = info.ip
				}
			}
		}
	}

	for _, intf := range append(intfList{intf}, secondaryList...) {
		// Link interface with router and vice versa.
		r.interfaces.push(intf)
		intf.router = r
		intf.ipV6 = r.ipV6
		name := intf.name
		iName := name[len("interface:"):]
		if _, found := s.routerIntf[iName]; found {
			errMsg("Duplicate definition of %s in %s", name, r)
		}
		s.routerIntf[iName] = intf
	}
}

func setupService(v *ast.Service, s *symbolTable) {
	name := v.Name
	v6 := v.IPV6
	sName := name[len("service:"):]
	sv := s.service[sName]
	sv.name = name
	sv.ipV6 = v6
	if d := v.Description; d != nil {
		sv.description = strings.TrimSuffix(strings.TrimSpace(d.Text), ";")
	}
	for _, a := range v.Attributes {
		switch a.Name {
		case "sub_owner":
			sv.subOwner = getRealOwnerRef(a, s, name)
		case "overlaps":
			sv.overlaps = tryServiceRefList(a, s, "attribute 'overlaps' of "+name)
		case "multi_owner":
			sv.multiOwner = getFlag(a, name)
		case "unknown_owner":
			sv.unknownOwner = getFlag(a, name)
		case "has_unenforceable":
			sv.hasUnenforceable = getFlag(a, name)
		case "disabled":
			sv.disabled = getFlag(a, name)
		case "disable_at":
			sv.disableAt = getSingleValue(a, "'disable_at' of "+name)
			if dateIsReached(sv.disableAt, "'disable_at' of "+name) {
				sv.disabled = true
			}
		default:
			errMsg("Unexpected attribute in %s: %s", name, a.Name)
		}
	}
	if sv.overlaps != nil {
		sv.overlapsUsed = make(map[*service]bool)
	}
	elements := func(a *ast.NamedUnion) []ast.Element {
		l := a.Elements
		if len(l) == 0 {
			warnMsg("%s of %s is empty", a.Name, name)
		}
		return l
	}
	sv.foreach = v.Foreach
	sv.user = elements(v.User)
	for _, v2 := range v.Rules {
		ru := new(unexpRule)
		ru.service = sv
		if v2.Deny {
			ru.action = "deny"
		} else {
			ru.action = "permit"
		}
		ru.src = elements(v2.Src)
		ru.dst = elements(v2.Dst)
		srcUser := checkUserInUnion(ru.src, "'src' of "+name)
		dstUser := checkUserInUnion(ru.dst, "'dst' of "+name)
		if !(srcUser || dstUser) {
			errMsg("Each rule of %s must use keyword 'user'", name)
		}
		if sv.foreach && !(srcUser && dstUser) {
			warnMsg(
				"Each rule of %s should reference 'user' in 'src' and 'dst'\n"+
					" because service has keyword 'foreach'", name)
		}
		if srcUser && dstUser {
			ru.hasUser = "both"
		} else if srcUser {
			ru.hasUser = "src"
		} else {
			ru.hasUser = "dst"
		}
		ru.prt = expandProtocols(getValueList(v2.Prt, name), s, v6, name)
		if a2 := v2.Log; a2 != nil {
			l := getIdentifierList(a2, name)
			sort.Strings(l)
			prev := ""
			j := 0
			for _, tag := range l {
				if tag == prev {
					warnMsg("Duplicate '%s' in log of %s", tag, name)
				} else {
					prev = tag
					l[j] = tag
					j++
				}
			}
			ru.log = strings.Join(l[:j], ",")
		}
		sv.rules = append(sv.rules, ru)
	}
}

func isUser(l []ast.Element) bool {
	if len(l) == 1 {
		_, ok := l[0].(*ast.User)
		return ok
	}
	return false
}

func checkUserInUnion(l []ast.Element, ctx string) bool {
	count := countUser(l, ctx)
	if !(count == 0 || count == len(l)) {
		errMsg("The sub-expressions of union in %s equally must\n"+
			" either reference 'user' or must not reference 'user'", ctx)
	}
	return count > 0
}

func checkUserInIntersection(l []ast.Element, ctx string) bool {
	return countUser(l, ctx) > 0
}

func countUser(l []ast.Element, ctx string) int {
	count := 0
	for _, el := range l {
		if hasUser(el, ctx) {
			count++
		}
	}
	return count
}

func hasUser(el ast.Element, ctx string) bool {
	switch x := el.(type) {
	case *ast.User:
		return true
	case ast.AutoElem:
		return checkUserInUnion(x.GetElements(), ctx)
	case *ast.Intersection:
		return checkUserInIntersection(x.Elements, ctx)
	case *ast.Complement:
		return hasUser(x.Element, ctx)
	default:
		return false
	}
}

func splitCheckTypedName(s string) (string, string) {
	typ, name := splitTypedName(s)
	if !isSimpleName(name) {
		errMsg("Invalid identifier in definition of '%s'", s)
	}
	return typ, name
}

func splitTypedName(s string) (string, string) {
	i := strings.Index(s, ":")
	return s[:i], s[i+1:]
}

func fullHostname(hName, nName string) string {
	_, name2 := splitTypedName(hName)

	// Make ID unique by appending name of enclosing network.
	if strings.HasPrefix(name2, "id:") {
		name2 += "." + nName
	}
	return name2
}

func checkDuplicate(l []ast.Toplevel) {
	seen := make(map[string]string)
	check := func(name, fName string) {
		if where := seen[name]; where != "" {
			if fName != where {
				where += " and " + fName
			}
			errMsg("Duplicate definition of %s in %s", name, where)
		}
		seen[name] = fName
	}
	for _, a := range l {
		topName := a.GetName()
		fileName := a.FileName()
		_, name := splitTypedName(topName)
		switch x := a.(type) {
		case *ast.Network:
			for _, a := range x.Hosts {
				name2 := fullHostname(a.Name, name)
				check("host:"+name2, fileName)
			}
		case *ast.Router:
			if x.IPV6 {
				topName = "IPv6 " + topName
			}
		}
		check(topName, fileName)
	}
}

func checkDuplAttr(l []*ast.Attribute, ctx string) {
	seen := make(map[string]bool)
	for _, a := range l {
		if seen[a.Name] {
			errMsg("Duplicate attribute '%s' in %s", a.Name, ctx)
		} else {
			seen[a.Name] = true
		}
	}
}

func emptyAttr(a *ast.Attribute) bool {
	return a.ComplexValue == nil && a.ValueList == nil
}

func getFlag(a *ast.Attribute, ctx string) bool {
	if !emptyAttr(a) {
		errMsg("No value expected for flag '%s' of %s", a.Name, ctx)
	}
	return true
}

func getSingleValue(a *ast.Attribute, ctx string) string {
	if a.ComplexValue != nil || len(a.ValueList) != 1 {
		errMsg("Single value expected in '%s' of %s", a.Name, ctx)
		return ""
	}
	return a.ValueList[0].Value
}

func getValueList(a *ast.Attribute, ctx string) stringList {
	if a.ComplexValue != nil || a.ValueList == nil {
		errMsg("List of values expected in '%s' of %s", a.Name, ctx)
		return nil
	}
	result := make(stringList, 0, len(a.ValueList))
	for _, v := range a.ValueList {
		result.push(v.Value)
	}
	return result
}

func getComplexValue(a *ast.Attribute, ctx string) []*ast.Attribute {
	l := a.ComplexValue
	if l == nil || a.ValueList != nil {
		errMsg("Structured value expected in '%s' of %s", a.Name, ctx)
	}
	aCtx := a.Name
	if ctx != "" {
		aCtx += " of " + ctx
	}
	checkDuplAttr(l, aCtx)
	return l
}

func getIdentifier(a *ast.Attribute, ctx string) string {
	v := getSingleValue(a, ctx)
	if !isSimpleName(v) {
		errMsg("Invalid identifier in '%s' of %s: %s", a.Name, ctx, v)
	}
	return v
}

func getIdentifierList(a *ast.Attribute, ctx string) []string {
	l := getValueList(a, ctx)
	for _, v := range l {
		if !isSimpleName(v) {
			errMsg("Invalid identifier in '%s' of %s: %s", a.Name, ctx, v)
		}
	}
	return l
}

// Check for valid email address.
// Local part definition from wikipedia,
// without space and other quoted characters.
// Only 7 bit ASCII.
var emailRegex = regexp.MustCompile(
	"^[\\w.!#$%&\"*+\\/=?^_\\{|}~`-]+@[\\w.-]+$")

func getEmailList(a *ast.Attribute, ctx string) []string {
	l := getValueList(a, ctx)
	for i, m := range l {
		switch {
		case emailRegex.MatchString(m):
		case m == "guest":
		case a.Name == "watchers":
			if i := strings.Index(m, "@"); i != -1 {
				loc := m[:i]
				dom := m[i+1:]
				if loc == "[all]" && isDomain(dom) {
					break
				}
			}
			fallthrough
		default:
			errMsg("Invalid email address (ASCII only) in %s of %s: %s",
				a.Name, ctx, m)
		}
		l[i] = strings.ToLower(m)
	}
	return removeDupl(l, a.Name+" of "+ctx)
}

// Setup standard time units with different names and plural forms.
var timeunits = map[string]int{
	"sec":    1,
	"second": 1,
	"min":    60,
	"minute": 60,
	"hour":   3600,
	"day":    86400,
}

func init() {
	for k, v := range timeunits {
		timeunits[k+"s"] = v
	}
}

// Read time value in different units, return seconds.
func getTimeVal(a *ast.Attribute, ctx string) int {
	v := getSingleValue(a, ctx)
	l := strings.Split(v, " ")
	bad := func() int {
		errMsg("Expected 'NUM sec|min|hour|day' in '%s' of %s", a.Name, ctx)
		return -1
	}
	if len(l) != 2 {
		return bad()
	}
	i, err := strconv.Atoi(l[0])
	if err != nil || i < 0 {
		return bad()
	}
	unit := l[1]
	factor, found := timeunits[unit]
	if !found {
		return bad()
	}
	return i * factor
}

func getTimeKilobytesPair(a *ast.Attribute, ctx string) *[2]int {
	v := getSingleValue(a, ctx)
	l := strings.Split(v, " ")
	bad := func() int {
		errMsg("Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in '%s' of %s",
			a.Name, ctx)
		return 0
	}
	time := func(v1, v2 string) int {
		i, err := strconv.Atoi(v1)
		if err != nil {
			return bad()
		}
		unit := v2
		factor, found := timeunits[unit]
		if !found {
			return bad()
		}
		return i * factor
	}
	kbytes := func(v1, v2 string) int {
		i, err := strconv.Atoi(v1)
		if err != nil {
			return bad()
		}
		if v2 != "kilobytes" {
			return bad()
		}
		return i
	}
	sec := -1
	kb := -1
	switch len(l) {
	case 2:
		if l[1] == "kilobytes" {
			kb = kbytes(l[0], l[1])
		} else {
			sec = time(l[0], l[1])
		}
	case 4:
		sec = time(l[0], l[1])
		kb = kbytes(l[2], l[3])
	default:
		errMsg("Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in '%s' of %s",
			a.Name, ctx)
	}
	return &[2]int{sec, kb}
}

func removeDupl(l []string, ctx string) []string {
	seen := make(map[string]bool)
	var dupl stringList
	j := 0
	for _, s := range l {
		if seen[s] {
			dupl.push(s)
		} else {
			seen[s] = true
			l[j] = s
			j++
		}
	}
	if dupl != nil {
		errMsg("Duplicates in %s: %s", ctx, strings.Join(dupl, ", "))
	}
	return l[:j]
}

func getManaged(a *ast.Attribute, ctx string) string {
	if emptyAttr(a) {
		return "standard"
	}
	v := getSingleValue(a, ctx)
	switch v {
	case "secondary", "standard", "full", "primary", "local", "routing_only":
		return v
	}
	errMsg("Invalid value for '%s' of %s: %s", a.Name, ctx, v)
	return ""
}

var routerInfo = map[string]*model{
	"IOS": &model{
		routing:         "IOS",
		filter:          "IOS",
		stateless:       true,
		statelessSelf:   true,
		statelessICMP:   true,
		inversedACLMask: true,
		canVRF:          true,
		canLogDeny:      true,
		logModifiers:    map[string]string{"log-input": ":subst"},
		hasOutACL:       true,
		needProtect:     true,
		crypto:          "IOS",
		printRouterIntf: true,
		commentChar:     "!",
	},
	"NX-OS": {
		routing:         "NX-OS",
		filter:          "NX-OS",
		stateless:       true,
		statelessSelf:   true,
		statelessICMP:   true,
		canObjectgroup:  true,
		inversedACLMask: true,
		usePrefix:       true,
		canVRF:          true,
		canLogDeny:      true,
		logModifiers:    map[string]string{},
		hasOutACL:       true,
		needProtect:     true,
		printRouterIntf: true,
		commentChar:     "!",
	},
	"ASA": {
		routing: "ASA",
		filter:  "ASA",
		logModifiers: map[string]string{
			"emergencies":   "0",
			"alerts":        "1",
			"critical":      "2",
			"errors":        "3",
			"warnings":      "4",
			"notifications": "5",
			"informational": "6",
			"debugging":     "7",
			"disable":       "disable",
		},
		statelessICMP:    true,
		hasOutACL:        true,
		canACLUseRealIP:  true,
		canObjectgroup:   true,
		canDynCrypto:     true,
		crypto:           "ASA",
		noCryptoFilter:   true,
		commentChar:      "!",
		noFilterICMPCode: true,
		needACL:          true,
	},
	"Linux": {
		routing:     "iproute",
		filter:      "iptables",
		hasIoACL:    true,
		commentChar: "#",
	},
}

func init() {
	for name := range routerInfo {
		// Is changed for model with extension. Used in error messages.
		routerInfo[name].name = name
		// Is left unchanged with extensions. Used in header of generated files.
		routerInfo[name].class = name
	}
}

func getModel(a *ast.Attribute, ctx string) *model {
	l := getValueList(a, ctx)
	m := l[0]
	attributes := l[1:]
	orig, found := routerInfo[m]
	if !found {
		errMsg("Unknown model in %s: %s", ctx, m)

		// Prevent further errors.
		return &model{name: m}
	}
	info := *orig
	if len(attributes) > 0 {
		add := ""
		for _, att := range attributes {
			add += ", " + att
			switch m {
			case "IOS":
				switch att {
				case "EZVPN":
					info.crypto = "EZVPN"
				case "FW":
					info.stateless = false
				default:
					goto FAIL
				}
			case "ASA":
				switch att {
				case "VPN":
					info.crypto = "ASA_VPN"
					info.doAuth = true
				case "CONTEXT":
					info.cryptoInContext = true
				case "EZVPN":
					info.crypto = "ASA_EZVPN"
				default:
					goto FAIL
				}
			default:
				goto FAIL
			}
			continue
		FAIL:
			errMsg("Unknown extension in '%s' of %s: %s", a.Name, ctx, att)
		}
		info.name += add
	}
	return &info
}

// Definition of dynamic routing protocols.
var routingInfo = map[string]*routing{
	"EIGRP": &routing{
		name:  "EIGRP",
		prt:   &proto{proto: "88"},
		mcast: mcastInfo{v4: []string{"224.0.0.10"}, v6: []string{"ff02::a"}},
	},
	"OSPF": &routing{
		name: "OSPF",
		prt:  &proto{proto: "89"},
		mcast: mcastInfo{v4: []string{"224.0.0.5", "224.0.0.6"},
			v6: []string{"ff02::5", "ff02::6"}},
	},
	"RIPv2": &routing{
		name: "RIP",
		prt:  &proto{proto: "udp", ports: [2]int{520, 520}},
		mcast: mcastInfo{v4: []string{"224.0.0.9"},
			v6: []string{"ff02::9"}},
	},
	"dynamic": &routing{name: "dynamic"},

	// Identical to 'dynamic', but must only be applied to router, not
	// to routerIntf.
	"manual": &routing{name: "manual"},
}

func getRouting(a *ast.Attribute, ctx string) *routing {
	v := getSingleValue(a, ctx)
	r := routingInfo[v]
	if r == nil {
		errMsg("Unknown routing protocol in '%s' of %s", a.Name, ctx)
	}
	return r
}

// Definition of redundancy protocols.
var xxrpInfo = map[string]*xxrp{
	"VRRP": &xxrp{
		prt:   &proto{proto: "112"},
		mcast: mcastInfo{v4: []string{"224.0.0.18"}, v6: []string{"ff02::12"}},
	},
	"HSRP": &xxrp{
		prt: &proto{proto: "udp", ports: [2]int{1985, 1985}},
		mcast: mcastInfo{v4: []string{"224.0.0.2"},

			// No official IPv6 multicast address for HSRP available,
			// therefore using IPv4 equivalent.
			v6: []string{"::e000:2"}},
	},
	"HSRPv2": &xxrp{
		prt: &proto{proto: "udp", ports: [2]int{1985, 1985}},
		mcast: mcastInfo{v4: []string{"224.0.0.102"},
			v6: []string{"ff02::66"}},
	},
}

func getVirtual(a *ast.Attribute, v6 bool, ctx string) *routerIntf {
	virtual := new(routerIntf)
	virtual.name = ctx + ".virtual"
	virtual.redundant = true
	vCtx := "'" + a.Name + "' of " + ctx
	l := getComplexValue(a, ctx)
	for _, a2 := range l {
		switch a2.Name {
		case "ip":
			virtual.ip = getIp(a2, v6, vCtx)
		case "type":
			t := getSingleValue(a2, vCtx)
			if _, found := xxrpInfo[t]; !found {
				errMsg("Unknown redundancy protocol in %s", vCtx)
			}
			virtual.redundancyType = t
		case "id":
			id := getSingleValue(a2, vCtx)
			num, err := strconv.Atoi(id)
			if err != nil {
				errMsg("Redundancy ID must be numeric in %s", vCtx)
			} else if !(num >= 0 || num < 256) {
				errMsg("Redundancy ID must be < 256 in %s", vCtx)
			}
			virtual.redundancyId = id
		default:
			errMsg("Unexpected attribute in %s: %s", vCtx, a2.Name)
		}
	}
	if virtual.ip == nil {
		errMsg("Missing IP in %s", vCtx)
		return nil
	}
	if virtual.redundancyId != "" && virtual.redundancyType == "" {
		errMsg("Redundancy ID is given without redundancy protocol in %s",
			vCtx)
	}
	return virtual
}

func isDomain(n string) bool {
	for _, part := range strings.Split(n, ".") {
		if !isSimpleName(part) {
			return false
		}
	}
	return n != ""
}

func isIdHostname(id string) bool {
	i := strings.Index(id, "@")
	// Leading "@" is ok.
	return (i <= 0 || isDomain(id[:i])) && isDomain(id[i+1:])
}

func getUserID(a *ast.Attribute, ctx string) string {
	id := getSingleValue(a, ctx)
	i := strings.Index(id, "@")
	if !(i > 0 && isDomain(id[:i]) && isDomain(id[i+1:])) {
		errMsg("Invalid '%s' in %s: %s", a.Name, ctx, id)
	}
	return id
}

func isSimpleName(n string) bool {
	return n != "" && strings.IndexAny(n, ".:/@") == -1
}

func getIp(a *ast.Attribute, v6 bool, ctx string) net.IP {
	return convIP(getSingleValue(a, ctx), v6, a.Name, ctx)
}

func getIpList(a *ast.Attribute, v6 bool, ctx string) []net.IP {
	var result []net.IP
	for _, v := range getValueList(a, ctx) {
		result = append(result, convIP(v, v6, a.Name, ctx))
	}
	return result
}

func getIpRange(a *ast.Attribute, v6 bool, ctx string) [2]net.IP {
	v := getSingleValue(a, ctx)
	l := strings.Split(v, " - ")
	var result [2]net.IP
	if len(l) != 2 {
		errMsg("Expected IP range in '%s' of %s", a.Name, ctx)
	} else {
		result[0] = convIP(l[0], v6, a.Name, ctx)
		result[1] = convIP(l[1], v6, a.Name, ctx)
	}
	return result
}

func getIpPrefix(a *ast.Attribute, v6 bool, ctx string) (net.IP, net.IPMask) {
	v := getSingleValue(a, ctx)
	n := convIpPrefix(v, v6, a.Name, ctx)
	if n == nil {
		return nil, nil
	}
	return n.IP, n.Mask
}

func getIpPrefixList(a *ast.Attribute, v6 bool, ctx string) []*net.IPNet {
	var result []*net.IPNet
	for _, v := range getValueList(a, ctx) {
		result = append(result, convIpPrefix(v, v6, a.Name, ctx))
	}
	return result
}

func convIpPrefix(s string, v6 bool, name, ctx string) *net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		errMsg("%s in '%s' of %s", err, name, ctx)
		return nil
	}
	if !n.IP.Equal(ip) {
		errMsg("IP and mask of %s don't match in '%s' of %s", s, name, ctx)
	}
	n.IP = getVxIP(n.IP, v6, name, ctx)
	return n
}

func convIP(s string, v6 bool, name, ctx string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		errMsg("Invalid IP address in '%s' of %s: %s", name, ctx, s)
		return nil
	}
	return getVxIP(ip, v6, name, ctx)
}

func getVxIP(ip net.IP, v6 bool, name, ctx string) net.IP {
	v4IP := ip.To4()
	if v6 {
		if v4IP != nil {
			errMsg("IPv6 address expected in '%s' of %s", name, ctx)
		}
		return ip
	} else if v4IP == nil {
		errMsg("IPv4 address expected in '%s' of %s", name, ctx)
	}
	return v4IP
}

func convToMask(prefix string, v6 bool, name, ctx string) net.IPMask {
	p, err := strconv.Atoi(prefix)
	if err == nil {
		size := 32
		if v6 {
			size = 128
		}
		mask := net.CIDRMask(p, size)
		if mask != nil {
			return mask
		}
	}
	errMsg("Invalid prefix in '%s' of %s", name, ctx)
	return nil
}

// Check if given date has been reached already.
var dateRegex = regexp.MustCompile(`^(\d\d\d\d-\d\d-\d\d)$`)

func dateIsReached(s, ctx string) bool {
	l := dateRegex.FindStringSubmatch(s)
	if l == nil {
		errMsg("Date expected as yyyy-mm-dd in %s", ctx)
		return false
	}
	date, _ := time.Parse("2006-01-02", s)
	return time.Now().After(date)
}

func getNetworkRef(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string) *network {

	return lookupNetworkRef(a, s, v6, ctx, false)
}

func tryNetworkRef(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string) *network {

	return lookupNetworkRef(a, s, v6, ctx, true)
}

func lookupNetworkRef(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string, warn bool) *network {

	typ, name := getTypedName(a, ctx)
	if typ == "" {
		return nil
	}
	ctx2 := "'" + a.Name + "' of " + ctx
	if typ != "network" {
		errMsg("Must only use network name in %s", ctx2)
		return nil
	}
	n := s.network[name]
	if n == nil {
		f := errMsg
		if warn {
			f = warnMsg
		}
		f("Referencing undefined network:%s in %s", name, ctx2)
		return nil
	}
	checkV4V6CrossRef(n, v6, ctx2)
	return n
}

func tryNetworkRefList(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string) netList {

	l := getValueList(a, ctx)
	result := make(netList, 0, len(l))
	ctx2 := "'" + a.Name + "' of " + ctx
	for _, v := range l {
		name := strings.TrimPrefix(v, "network:")
		if len(name) == len(v) {
			errMsg("Expected type 'network:' in %s", ctx2)
		} else if n, found := s.network[name]; found {
			checkV4V6CrossRef(n, v6, ctx2)
			result = append(result, n)
		} else {
			warnMsg("Ignoring undefined network:%s in %s", name, ctx2)
		}
	}
	return result
}

func tryHostRef(a *ast.Attribute, s *symbolTable, v6 bool, ctx string) *host {
	typ, name := getTypedName(a, ctx)
	ctx2 := "'" + a.Name + "' of " + ctx
	if typ != "host" {
		errMsg("Must only use host name in %s", ctx2)
		return nil
	}
	h := s.host[name]
	if h == nil {
		warnMsg("Ignoring undefined host:%s in %s", name, ctx2)
		return nil
	}
	checkV4V6CrossRef(h, v6, ctx2)
	return h
}

func getTypedName(a *ast.Attribute, ctx string) (string, string) {
	v := getSingleValue(a, ctx)
	i := strings.Index(v, ":")
	if i == -1 {
		errMsg("Typed name expected in '%s' of %s", a.Name, ctx)
		return "", ""
	}
	return v[:i], v[i+1:]
}

func getRealOwnerRef(a *ast.Attribute, s *symbolTable, ctx string) *owner {
	o := tryOwnerRef(a, s, ctx)
	if o != nil {
		if o.admins == nil {
			errMsg("Missing attribute 'admins' in %s of %s", o.name, ctx)
			o.admins = make([]string, 0)
		}
		if o.onlyWatch {
			errMsg("%s with attribute 'only_watch' must only be used at area,\n"+
				" not at %s", o.name, ctx)
			o.onlyWatch = false
		}
	}
	return o
}

func tryOwnerRef(a *ast.Attribute, s *symbolTable, ctx string) *owner {
	name := getIdentifier(a, ctx)
	o := s.owner[name]
	if o == nil {
		warnMsg("Ignoring undefined owner:%s of %s", name, ctx)
	}
	return o
}

func getIsakmpRef(a *ast.Attribute, s *symbolTable, ctx string) *isakmp {
	typ, name := getTypedName(a, ctx)
	if typ != "isakmp" {
		errMsg("Must only use isakmp type in '%s' of %s", a.Name, ctx)
		return nil
	}
	is := s.isakmp[name]
	if is == nil {
		errMsg("Can't resolve reference to isakmp:%s in %s", name, ctx)
	}
	return is
}

func getIpsecRef(a *ast.Attribute, s *symbolTable, ctx string) *ipsec {
	typ, name := getTypedName(a, ctx)
	if typ != "ipsec" {
		errMsg("Must only use ipsec type in '%s' of %s", a.Name, ctx)
		return nil
	}
	is := s.ipsec[name]
	if is == nil {
		errMsg("Can't resolve reference to ipsec:%s in %s", name, ctx)
	}
	return is
}

func getCryptoRef(a *ast.Attribute, s *symbolTable, ctx string) *crypto {
	typ, name := getTypedName(a, ctx)
	if typ != "crypto" {
		errMsg("Must only use crypto name in '%s' of %s", a.Name, ctx)
		return nil
	}
	cr := s.crypto[name]
	if cr == nil {
		errMsg("Can't resolve reference to crypto:%s in '%s' of %s",
			name, a.Name, ctx)
	}
	return cr
}

func getCryptoRefList(a *ast.Attribute, s *symbolTable, ctx string) []*crypto {
	l := getValueList(a, ctx)
	result := make([]*crypto, 0, len(l))
	ctx2 := "'" + a.Name + "' of " + ctx
	for _, v := range l {
		name := strings.TrimPrefix(v, "crypto:")
		if len(name) == len(v) {
			errMsg("Expected type 'crypto:' in %s", ctx2)
		} else if cr, found := s.crypto[name]; found {
			result = append(result, cr)
		} else {
			errMsg("Can't resolve reference to crypto:%s in %s", name, ctx2)
		}
	}
	return result
}

func tryServiceRefList(
	a *ast.Attribute, s *symbolTable, ctx string) []*service {

	l := getValueList(a, ctx)
	result := make([]*service, 0, len(l))
	for _, v := range l {
		name := strings.TrimPrefix(v, "service:")
		if len(name) == len(v) {
			errMsg("Expected type 'service:' in %s", ctx)
		} else if s, found := s.service[name]; found {
			result = append(result, s)
		} else {
			warnMsg("Unknown '%s' in %s", v, ctx)
		}
	}
	return result
}

func getProtocolRef(name string, s *symbolTable, ctx string) *proto {
	p := s.protocol[name]
	if p == nil {
		errMsg("Can't resolve reference to protocol:%s in %s", name, ctx)
	} else {
		p.isUsed = true
	}
	return p
}

func getProtocolList(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string) protoList {

	l := getValueList(a, ctx)
	ctx2 := a.Name + " of " + ctx
	return expandProtocols(l, s, v6, ctx2)
}

func expandProtocols(
	l stringList, s *symbolTable, v6 bool, ctx string) protoList {

	var result protoList
	for _, v := range l {
		if strings.HasPrefix(v, "protocol:") {
			name := v[len("protocol:"):]
			if p := getProtocolRef(name, s, ctx); p != nil {
				result.push(p)
			}
		} else if strings.HasPrefix(v, "protocolgroup:") {
			name := v[len("protocolgroup:"):]
			result = append(result, expandProtocolgroup(name, s, v6, ctx)...)
		} else {
			p := getSimpleProtocol(v, v6, "'"+v+"' of "+ctx)
			p = cacheUnnamedProtocol(p, s)
			result.push(p)
		}
	}
	return result
}

func expandProtocolgroup(
	name string, s *symbolTable, v6 bool, ctx string) protoList {

	g, found := s.protocolgroup[name]
	if !found {
		errMsg("Can't resolve reference to protocolgroup:%s in %s", name, ctx)
		return nil
	}
	if g.recursive {
		errMsg("Found recursion in definition of %s", ctx)
	} else if !g.isUsed {
		g.isUsed = true
		g.recursive = true
		ctx2 := "protocolgroup:" + name
		g.elements = expandProtocols(g.list, s, v6, ctx2)
		g.recursive = false
	}
	return g.elements
}

func cacheUnnamedProtocol(p *proto, s *symbolTable) *proto {
	name := genProtocolName(p)
	if cached, found := s.unnamedProto[name]; found {
		return cached
	}
	p.name = name
	s.unnamedProto[name] = p
	return p
}

// Creates a readable, unique name for passed protocol,
// e.g. "tcp 80" for { proto : "tcp", ports: [80, 80] }.
func genProtocolName(p *proto) string {
	pr := p.proto
	switch pr {
	case "ip":
		return pr
	case "tcp", "udp":
		portName := func(p *proto) string {
			if p == nil {
				return ""
			}
			n := p.ports
			v1, v2 := n[0], n[1]
			if v1 == v2 {
				return strconv.Itoa(v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else {
				return strconv.Itoa(v1) + "-" + strconv.Itoa(v2)
			}
		}
		var port string
		if s := portName(p.src); s != "" {
			port = s + ":"
		}
		if d := portName(p.dst); d != "" {
			port += d
		}
		if port != "" {
			return pr + " " + port
		}
		return pr
	case "icmp":
		result := pr
		if p.icmpType != -1 {
			result += " " + strconv.Itoa(p.icmpType)
			if p.icmpCode != -1 {
				result += "/" + strconv.Itoa(p.icmpCode)
			}
		}
		return result
	default:
		return "proto " + pr
	}
}

func getRadiusAttributes(a *ast.Attribute, ctx string) map[string]string {
	result := make(map[string]string)
	rCtx := a.Name + " of " + ctx
	l := getComplexValue(a, ctx)
	for _, a2 := range l {
		k := a2.Name
		if !isSimpleName(k) {
			errMsg("Invalid identifier '%s' in %s", k, rCtx)
		}
		v := ""
		if len(a2.ValueList) == 1 {
			v = a2.ValueList[0].Value
		}
		result[k] = v
	}
	return result
}

func getRouterAttributes(
	a *ast.Attribute, s *symbolTable, ar *area) *routerAttributes {

	ctx := ar.name
	r := new(routerAttributes)
	name := "router_attributes of " + ctx
	r.name = name
	l := getComplexValue(a, ctx)
	for _, a2 := range l {
		switch a2.Name {
		case "owner":
			r.owner = getRealOwnerRef(a2, s, name)
		case "policy_distribution_point":
			r.policyDistributionPoint = tryHostRef(a2, s, ar.ipV6, name)
		case "general_permit":
			r.generalPermit = getGeneralPermit(a2, s, ar.ipV6, name)
		default:
			errMsg("Unexpected attribute in %s: %s", name, a2.Name)
		}
	}
	return r
}

func getGeneralPermit(
	a *ast.Attribute, s *symbolTable, v6 bool, ctx string) protoList {

	l := getProtocolList(a, s, v6, ctx)
	prtTCP := s.unnamedProto["tcp"]
	for i, p := range l {
		// Check for protocols not valid for general_permit.
		// Don't allow port ranges. This wouldn't work, because
		// genReverseRules doesn't handle generally permitted protocols.
		var reason stringList
		if p.modifiers != nil {
			reason.push("modifiers")
		}
		if p.src != nil || p.dst != nil && p.dst != prtTCP.dst {
			reason.push("ports")
		}
		if reason != nil {
			errMsg("Must not use '%s' with %s in general_permit of %s",
				p.name, strings.Join(reason, " or "), ctx)
		}
		// Ony use destination port.
		if d := p.dst; d != nil {
			l[i] = d
		}
	}
	// Sort protocols by name, so we can compare value lists of
	// attribute general_permit for redundancy during inheritance.
	sort.Slice(l, func(i, j int) bool { return l[i].name < l[j].name })
	return l
}

func addLog(a *ast.Attribute, r *router) bool {
	if !strings.HasPrefix(a.Name, "log:") {
		return false
	}
	_, name := splitCheckTypedName(a.Name)
	modifier := ""
	if !emptyAttr(a) {
		modifier = getSingleValue(a, r.name)
	}
	m := r.log
	if m == nil {
		m = make(map[string]string)
		r.log = m
	}
	m[name] = modifier
	return true
}

func addAttr(
	a *ast.Attribute, attr map[string]string, ctx string) map[string]string {
	v := getSingleValue(a, ctx)
	switch v {
	case "restrict", "enable", "ok":
		if attr == nil {
			attr = make(map[string]string)
		}
		attr[a.Name] = v
		return attr
	}
	errMsg("Expected 'restrict', 'enable' or 'ok' in '%s' of %s", a.Name, ctx)
	return attr
}

func addNetNat(a *ast.Attribute, m map[string]*network, v6 bool,
	s *symbolTable, ctx string) map[string]*network {

	return addXNat(a, m, v6, s, ctx, getIpPrefix)
}
func addIntfNat(a *ast.Attribute, m map[string]*network, v6 bool,
	s *symbolTable, ctx string) map[string]*network {

	return addXNat(a, m, v6, s, ctx,
		func(a *ast.Attribute, v6 bool, ctx string) (net.IP, net.IPMask) {
			ip := getSingleValue(a, ctx)
			return convIP(ip, v6, a.Name, ctx), getHostMask(v6)
		})
}

func addXNat(a *ast.Attribute, m map[string]*network, v6 bool, s *symbolTable,
	ctx string, getIpX func(*ast.Attribute, bool, string) (net.IP, net.IPMask),
) map[string]*network {

	if !strings.HasPrefix(a.Name, "nat:") {
		return nil
	}
	_, tag := splitCheckTypedName(a.Name)
	nat := new(network)
	natCtx := a.Name + " of " + ctx
	l := getComplexValue(a, ctx)
	for _, a2 := range l {
		switch a2.Name {
		case "ip":
			nat.ip, nat.mask = getIpX(a2, v6, natCtx)
		case "hidden":
			nat.hidden = getFlag(a2, natCtx)
		case "identity":
			nat.identity = getFlag(a2, natCtx)
		case "dynamic":
			nat.dynamic = getFlag(a2, natCtx)
		case "subnet_of":
			nat.subnetOf = tryNetworkRef(a2, s, v6, natCtx)
		default:
			errMsg("Unexpected attribute in %s: %s", natCtx, a2.Name)
		}
	}
	if nat.hidden {
		for _, a2 := range l {
			if a2.Name != "hidden" {
				errMsg("Hidden NAT must not use attribute '%s' in %s",
					a2.Name, natCtx)
			}
		}

		// This simplifies error checks for overlapping addresses.
		nat.dynamic = true

		// Provide an unusable address.
		nat.ip = getZeroIp(v6)
		nat.mask = getHostMask(v6)
	} else if nat.identity {
		for _, a2 := range l {
			if a2.Name != "identity" {
				errMsg("Identity NAT must not use attribute '%s' in %s",
					a2.Name, natCtx)
			}
		}
		nat.dynamic = true
	} else if nat.ip == nil {
		errMsg("Missing IP address in %s", natCtx)
	}

	// Attribute .natTag is used later to look up static translation
	// of hosts inside a dynamically translated network.
	nat.natTag = tag

	nat.name = ctx
	nat.descr = "nat:" + tag + " of " + ctx
	if m == nil {
		m = make(map[string]*network)
	}
	m[tag] = nat
	return m
}

func addIPNat(a *ast.Attribute, m map[string]net.IP, v6 bool,
	ctx string) map[string]net.IP {

	if !strings.HasPrefix(a.Name, "nat:") {
		return nil
	}
	_, name := splitCheckTypedName(a.Name)
	var ip net.IP
	natCtx := a.Name + " of " + ctx
	l := getComplexValue(a, ctx)
	for _, a2 := range l {
		switch a2.Name {
		case "ip":
			ip = getIp(a2, v6, natCtx)
		default:
			errMsg("Unexpected attribute in %s: %s", natCtx, a2.Name)
		}
	}
	if m == nil {
		m = make(map[string]net.IP)
	}
	m[name] = ip
	return m
}

// Store defining log tags in knownLog.
func collectLog(m map[string]string) {
	for tag, _ := range m {
		knownLog[tag] = true
	}
}

func checkInterfaceIp(intf *routerIntf, n *network) {
	if intf.unnumbered {
		if !n.unnumbered {
			errMsg("Unnumbered %s must not be linked to %s", intf, n)
		}
		return
	}
	if n.unnumbered {
		errMsg("%s must not be linked to unnumbered %s", intf, n)
		return
	}
	if intf.negotiated || intf.bridged {
		// Nothing to be checked: attribute 'bridged' is set automatically
		// for an interface without IP and linked to bridged network.
		return
	}

	// Check compatibility of interface IP and network IP/mask.
	ip := intf.ip
	nIP := n.ip
	mask := n.mask
	if !matchIp(ip, nIP, mask) {
		errMsg("%s's IP doesn't match %s's IP/mask", intf, n)
	}
	if isHostMask(mask) {
		warnMsg("%s has address of its network.\n"+
			" Remove definition of %s and\n"+
			" add attribute 'loopback' at interface definition.",
			intf, n)
	} else if !n.ipV6 {

		// Check network and broadcast address only for IPv4,
		// but not for /31 IPv4 (see RFC 3021).
		len, _ := mask.Size()
		if len != 31 {
			if bytes.Compare(ip, nIP) == 0 {
				errMsg("%s has address of its network", intf)
			}
			if bytes.Compare(ip, getBroadcastIP(n)) == 0 {
				errMsg("%s has broadcast address", intf)
			}
		}
	}
}

//############################################################################
// Purpose  : Moves attribute 'no_in_acl' from interface to hardware because
//            ACLs operate on hardware, not on logic. Marks hardware needing
//            outgoing ACLs.
// Comments : Not more than 1 'no_in_acl' interface per router allowed.
func checkNoInAcl(r *router) {
	count := 0
	hasCrypto := false
	var rerouteIntf *routerIntf

	// Move attribute no_in_acl to hardware.
	for _, intf := range r.interfaces {
		if intf.spoke != nil || intf.hub != nil {
			hasCrypto = true
		}
		if intf.reroutePermit != nil && !intf.noInAcl {
			rerouteIntf = intf
		}
		if !intf.noInAcl {
			continue
		}
		hw := intf.hardware

		// Prevent duplicate error message.
		if hw.noInAcl {
			continue
		}
		hw.noInAcl = true

		// Assure max number of main interfaces at no_in_acl-hardware == 1.
		if nonSecondaryIntfCount(hw.interfaces) != 1 {
			errMsg("Only one logical interface allowed at hardware '%s' of %s\n"+
				" because of attribute 'no_in_acl'", hw.name, r.name)
		}
		count++

		// Reference no_in_acl interface in router attribute.
		r.noInAcl = intf
	}
	if count == 0 {
		return
	}

	// Assert maximum number of 'no_in_acl' interfaces per router
	if count != 1 {
		errMsg("At most one interface of %s may use flag 'no_in_acl'", r)
	}

	// Assert router to support outgoing ACL
	if !r.model.hasOutACL {
		errMsg("%s doesn't support outgoing ACL", r)
	}

	// reroute_permit would generate permit any -> networks,
	// but no_in_acl would generate permit any -> any anyway.
	if r.noInAcl.reroutePermit != nil {
		warnMsg("Useless use of attribute 'reroute_permit' together with"+
			" 'no_in_acl' at %s", r.noInAcl.name)
	}

	// Must not use reroute_permit to network N together with no_in_acl.
	// In this case incoming traffic at no_in_acl interface
	// to network N wouldn't be filtered at all.
	if rerouteIntf != nil {
		errMsg("Must not use attributes no_in_acl and reroute_permit"+
			" together at %s\n"+
			" Add incoming and outgoing ACL line in raw file instead.", r)
	}

	// Assert router not to take part in crypto tunnels.
	if hasCrypto {
		errMsg(
			"Don't use attribute 'no_in_acl' together with crypto tunnel at %s",
			r)
	}

	// Mark other hardware with attribute 'need_out_acl'.
	for _, hw := range r.hardware {
		if !hw.noInAcl {
			hw.needOutAcl = true
		}
	}
}

// No traffic must traverse crypto interface.
// Hence split router into separate instances, one instance for each
// crypto interface.
// Split routers are tied by identical attribute .deviceName.
func moveLockedIntf(intf *routerIntf) {
	orig := intf.router

	// Use different and uniqe name for each split router.
	name := "router:" + intf.name[len("interface:"):]
	new := *orig
	new.name = name
	new.origRouter = orig
	new.interfaces = intfList{intf}
	intf.router = &new
	routerFragments = append(routerFragments, &new)

	// Don't check fragment for reachability.
	new.policyDistributionPoint = nil

	// Remove interface from old router.
	// Retain original interfaces.
	l := orig.interfaces
	if orig.origIntfs == nil {
		orig.origIntfs = l
	}
	orig.interfaces = make(intfList, 0, len(l)-1)
	for _, intf2 := range l {
		if intf2 != intf {
			orig.interfaces.push(intf2)
		}
	}

	if orig.managed != "" {
		hw := intf.hardware
		new.hardware = []*hardware{hw}
		l := orig.hardware
		orig.origHardware = l
		orig.hardware = make([]*hardware, 0, len(l)-1)
		for _, hw2 := range l {
			if hw2 != hw {
				orig.hardware = append(orig.hardware, hw2)
			}
		}

		for _, intf2 := range hw.interfaces {
			if intf2 != intf && !intf2.tunnel {
				errMsg("Crypto %s must not share hardware with other %s",
					intf, intf2)
				break
			}
		}

		// Copy map, because it is changed per device later.
		if m := orig.radiusAttributes; m != nil {
			m2 := make(map[string]string)
			for k, v := range m {
				m2[k] = v
			}
			new.radiusAttributes = m2
		}
	}
}

// Link tunnel networks with tunnel hubs.
func linkTunnels(s *symbolTable) {
	// ToDo: Check if sorting is only needed for deterministic error messages.
	sorted := make([]*crypto, 0, len(symTable.crypto))
	for _, c := range symTable.crypto {
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].name < sorted[j].name
	})
	for _, cr := range sorted {
		realHub := cr.hub
		if realHub == nil || realHub.disabled {
			warnMsg("No hub has been defined for %s", cr.name)
			continue
		}
		//realSpokes = [ grep { ! $_.disabled } realSpokes ]
		tunnels := cr.tunnels
		if len(tunnels) == 0 {
			warnMsg("No spokes have been defined for %s", cr.name)
		}

		isakmp := cr.ipsec.isakmp
		needId := isakmp.authentication == "rsasig"

		// Note: Crypto router is split internally into two nodes.
		// Typically we get get a node with only a single crypto interface.
		// Take original router with cleartext interface(s).
		r := realHub.router
		if orig := r.origRouter; orig != nil {
			r = orig
		}
		model := r.model
		rName := r.name[len("router:"):]

		// Router of type 'doAuth' can only check certificates,
		// not pre-shared keys.
		if model.doAuth && !needId {
			errMsg("%s needs authentication=rsasig in %s", r, isakmp.name)
		}

		if model.crypto == "EZVPN" {
			errMsg("Must not use %s of model '%s' as crypto hub", r, model.name)
		}

		// Generate a single tunnel from each spoke to single hub.
		for _, spokeNet := range tunnels {
			netName := spokeNet.name[len("network:"):]
			spoke := spokeNet.interfaces[0]
			realSpoke := spoke.realIntf

			hw := realHub.hardware
			hub := new(routerIntf)
			hub.name = "interface:" + rName + "." + netName
			hub.tunnel = true
			hub.crypto = cr
			// Attention: shared hardware between router and orig_router.
			hub.hardware = hw
			hub.isHub = true
			hub.realIntf = realHub
			hub.router = r
			hub.network = spokeNet
			hub.bindNat = realHub.bindNat
			hub.routing = realHub.routing
			hub.peer = spoke
			spoke.peer = hub
			r.interfaces.push(hub)
			hw.interfaces.push(hub)
			spokeNet.interfaces.push(hub)

			// We need hub also be available in orig_interfaces.
			if r.origIntfs != nil {
				r.origIntfs.push(hub)
			}

			if realSpoke.ip == nil {
				if !(model.doAuth || model.canDynCrypto) {
					errMsg(
						"%s can't establish crypto tunnel to %s with unknown IP",
						r, realSpoke)
				}
			}
		}
	}
}

// Collect groups of virtual interfaces
// - be connected to the same network and
// - having the same IP address.
// Link all virtual interfaces to the group of member interfaces.
// Check consistency:
// - Member interfaces must use identical protocol and identical ID.
// - The same ID must not be used by some other group
//   - connected to the same network
//   - emploing the same redundancy type
func linkVirtualInterfaces() {

	// Collect array of virtual interfaces with same IP at same network.
	type key1 struct {
		n  *network
		ip string
	}
	net2ip2virtual := make(map[key1]intfList)

	// Map to look up first virtual interface of a group
	// inside the same network and using the same ID and type.
	type key2 struct {
		n   *network
		id  string
		typ string
	}
	net2id2type2virtual := make(map[key2]*routerIntf)
	for _, v1 := range virtualInterfaces {
		if v1.disabled {
			continue
		}
		ip := v1.ip.String()
		n := v1.network
		t1 := v1.redundancyType
		id1 := v1.redundancyId
		k := key1{n, ip}
		l := net2ip2virtual[k]
		if l != nil {
			v2 := l[0]
			t2 := v2.redundancyType
			if t1 != t2 {
				errMsg("Must use identical redundancy protocol at\n"+
					" - %s\n"+
					" - %s", v2, v1)
			}
			id2 := v2.redundancyId
			if id1 != id2 {
				errMsg("Must use identical ID at\n"+
					" - %s\n"+
					" - %s", v2, v1)
			}
		} else {
			// Check for identical ID used at unrelated virtual interfaces
			// inside the same network.
			if id1 != "" {
				if v2 := net2id2type2virtual[key2{n, id1, t1}]; v2 != nil {
					errMsg("Must use different ID at unrelated\n"+
						" - %s\n"+
						" - %s", v2, v1)
				} else {
					net2id2type2virtual[key2{n, id1, t1}] = v1
				}
			}
		}
		l.push(v1)
		net2ip2virtual[k] = l
	}
	for _, l := range net2ip2virtual {
		for _, intf := range l {
			intf.redundancyIntfs = l
		}
	}

	// Automatically add pathrestriction to each group of virtual
	// interfaces, where at least one interface is managed.
	// Pathrestriction would be useless if all devices are unmanaged.
	for _, l := range net2ip2virtual {
		if len(l) < 2 {
			continue
		}
		for _, intf := range l {
			r := intf.router
			if r.managed != "" || r.routingOnly {
				name := "auto-virtual-" + intf.ip.String()
				addPathrestriction(name, l)
				break
			}
		}
	}
}

func addPathrestriction(name string, l intfList) {
	pr := new(pathRestriction)
	pr.name = name
	pr.elements = l
	pathrestrictions = append(pathrestrictions, pr)
	for _, intf := range l {
		//debug("%s at %s", name, intf)
		// Multiple restrictions may be applied to a single interface.
		intf.pathRestrict = append(intf.pathRestrict, pr)
		// Unmanaged router with pathrestriction is handled specially.
		// It is separating zones, but gets no code.
		if intf.router.managed == "" {
			intf.router.semiManaged = true
		}
	}
}

// If a pathrestriction or a bind_nat is added to an unmanged router,
// it is marked as semiManaged. As a consequence, a new zone would be
// created at each interface of this router.
// If an unmanaged router has a large number of interfaces, but only
// one or a few pathrestrictions or bind_nat attached, we would get a
// large number of useless zones.
// To reduce the number of newly created zones, we split an unmanaged
// router with pathrestrictions or bind_nat, if it has more than two
// interfaces without any pathrestriction or bind_nat:
// - original part having only interfaces without pathrestriction or bind_nat,
// - one split part for each interface with pathrestriction or bind_nat.
// All parts are connected by a freshly created unnumbered network.
func splitSemiManagedRouter() {
	for _, r := range getIpv4Ipv6Routers() {

		// Unmanaged router is marked as semi_managed, if
		// - it has pathrestriction,
		// - it has interface with bind_nat or
		// - is managed=routing_only.
		if !r.semiManaged {
			continue
		}

		// Don't split device with 'managed=routing_only'.
		if r.routingOnly {
			continue
		}

		// Count interfaces without pathrestriction or bind_nat.
		count := 0
		for _, intf := range r.interfaces {
			if intf.mainIntf == nil &&
				intf.pathRestrict == nil &&
				intf.bindNat == nil {
				count++
			}
		}
		if count < 2 {
			continue
		}

		// Retain copy of original interfaces for finding [all] interfaces.
		if r.origIntfs == nil {
			r.origIntfs = append(r.origIntfs, r.interfaces...)
		}

		// Split router into two or more parts.
		// Move each interface with pathrestriction or bind_nat and
		// corresponding secondary interface to new router.
		for i, intf := range r.interfaces {
			if intf.pathRestrict == nil && intf.bindNat == nil ||
				intf.mainIntf != nil {
				continue
			}

			// Create new semiManged router with identical name.
			// Add reference to original router having 'origIntfs'.
			nr := new(router)
			nr.name = r.name
			nr.semiManaged = true
			nr.origRouter = r
			intf.router = nr
			routerFragments = append(routerFragments, nr)

			// Link current and newly created router by unnumbered network.
			// Add reference to original interface at internal interface.
			iName := intf.name
			n := new(network)
			n.name = iName + "(split Network)"
			n.unnumbered = true
			intf1 := new(routerIntf)
			intf1.name = iName + "(split1)"
			intf1.unnumbered = true
			intf1.router = r
			intf1.network = n
			intf2 := new(routerIntf)
			intf2.name = iName + "(split2)"
			intf2.unnumbered = true
			intf2.router = nr
			intf2.network = n
			n.interfaces = intfList{intf1, intf2}
			nr.interfaces = intfList{intf2, intf}

			// Add reference to other interface at original interface
			// at newly created router. This is needed for post
			// processing in checkPathrestrictions.
			if intf.pathRestrict != nil {
				intf.splitOther = intf2
			}

			// Replace original interface at current router.
			r.interfaces[i] = intf1
		}

		// Original router is no longer semiManged.
		r.semiManaged = false

		// Move secondary interfaces, modify original list.
		l := r.interfaces
		j := 0
		for _, intf := range l {
			if m := intf.mainIntf; m != nil {
				nr := m.router
				if nr != r {
					intf.router = nr
					nr.interfaces.push(intf)
					continue
				}
			}
			l[j] = intf
			j++
		}
		r.interfaces = l[:j]
	}
}

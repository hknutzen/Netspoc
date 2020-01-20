package pass1

import (
	"fmt"
	"net"
)

type stringerList []fmt.Stringer

type stringList []string

func (a *stringList) push(e string) {
	*a = append(*a, e)
}

type autoExt struct {
	selector string
	managed  bool
}

type aggExt struct {
	ip   net.IP
	mask net.IPMask
}

type parsedObjRef struct {
	typ  string
	name interface{}
	ext  interface{}
}

type userInfo struct {
	elements groupObjList
}

type netOrRouter interface{}

type autoIntf struct {
	privateObj
	managed bool
	name    string
	object  netOrRouter
}

func (x autoIntf) String() string { return x.name }
func (x autoIntf) isDisabled() bool {
	switch x := x.object.(type) {
	case *router:
		return x.disabled
	case *network:
		return x.disabled
	}
	return false
}
func (x autoIntf) setUsed() {}

type groupObj interface {
	isDisabled() bool
	getPrivate() string
	setUsed()
	String() string
}
type groupObjList []groupObj

func (a *groupObjList) push(e groupObj) {
	*a = append(*a, e)
}

type ipVxGroupObj interface {
	groupObj
	isIPv6() bool
}

type srvObj interface {
	ownerer
	String() string
	getAttr(attr string) string
	getPrivate() string
	getNetwork() *network
	setCommon(m xMap) // for importFromPerl
}
type srvObjList []srvObj

func (a *srvObjList) push(e srvObj) {
	*a = append(*a, e)
}

type someObj interface {
	String() string
	getNetwork() *network
	getUp() someObj
	address(nn natSet) net.IPNet
	getAttr(attr string) string
	getPathNode() pathStore
	getZone() *zone
	setCommon(m xMap) // for importFromPerl
}

type disabledObj struct {
	disabled bool
}

func (x *disabledObj) isDisabled() bool { return x.disabled }

type ownedObj struct {
	owner *owner
}

func (x *ownedObj) getOwner() *owner  { return x.owner }
func (x *ownedObj) setOwner(o *owner) { x.owner = o }

type privateObj struct {
	private string
}

func (x *privateObj) getPrivate() string { return x.private }

type ipVxObj struct {
	ipV6 bool
}

func (x *ipVxObj) isIPv6() bool { return x.ipV6 }

type usedObj struct {
	isUsed bool
}

func (x *usedObj) setUsed() { x.isUsed = true }

type ownerer interface {
	getOwner() *owner
	setOwner(o *owner)
}

type ipObj struct {
	disabledObj
	ipVxObj
	ownedObj
	privateObj
	usedObj
	name       string
	ip         net.IP
	unnumbered bool
	negotiated bool
	short      bool
	tunnel     bool
	bridged    bool
}

func (x ipObj) String() string { return x.name }

type natMap map[string]*network

type network struct {
	ipObj
	attr             map[string]string
	certId           string
	crosslink        bool
	descr            string
	dynamic          bool
	filterAt         map[int]bool
	hasIdHosts       bool
	hasOtherSubnet   bool
	hasSubnets       bool
	hidden           bool
	hosts            []*host
	interfaces       []*routerIntf
	invisible        bool
	isAggregate      bool
	isLayer3         bool
	loopback         bool
	mask             net.IPMask
	maxRoutingNet    *network
	maxSecondaryNet  *network
	nat              map[string]*network
	natTag           string
	networks         netList
	radiusAttributes map[string]string
	subnetOf         *network
	subnets          []*subnet
	unstableNat      map[natSet]netList
	up               *network
	zone             *zone
}

func (x *network) getNetwork() *network { return x }
func (x *network) getUp() someObj {
	if x.up == nil {
		return nil
	}
	return x.up
}

type netList []*network

func (a *netList) push(e *network) {
	*a = append(*a, e)
}

type netObj struct {
	ipObj
	usedObj
	bindNat []string
	nat     map[string]net.IP
	network *network
	up      someObj
}

func (x *netObj) getNetwork() *network { return x.network }
func (x *netObj) getUp() someObj       { return x.up }

type subnet struct {
	netObj
	mask             net.IPMask
	hasNeighbor      bool
	id               string
	ldapId           string
	neighbor         *subnet
	radiusAttributes map[string]string
}

type host struct {
	netObj
	id               string
	ipRange          [2]net.IP
	ldapId           string
	radiusAttributes map[string]string
	subnets          []*subnet
}

type model struct {
	commentChar     string
	class           string
	crypto          string
	doAuth          bool
	canObjectgroup  bool
	cryptoInContext bool
	filter          string
	logModifiers    map[string]string
	needAcl         bool
	hasIoAcl        bool
	noCryptoFilter  bool
	printRouterIntf bool
	routing         string
	stateless       bool
	statelessSelf   bool
	statelessICMP   bool
	usePrefix       bool
}

// Use pointer to map, because we need to test natSet for equality,
// so we can use it as map key.
type natSet *map[string]bool

type aclInfo struct {
	name         string
	natSet       natSet
	dstNatSet    natSet
	rules        ruleList
	intfRules    ruleList
	protectSelf  bool
	addPermit    bool
	addDeny      bool
	filterAnySrc bool
	isStdACL     bool
	isCryptoACL  bool
	needProtect  []net.IPNet
	subAclList   []*aclInfo
}

type router struct {
	ipVxObj
	ownedObj
	privateObj
	pathStoreData
	pathObjData
	name                    string
	deviceName              string
	managed                 string
	semiManaged             bool
	adminIP                 []string
	model                   *model
	log                     map[string]string
	logDeny                 bool
	localMark               int
	origIntfs               []*routerIntf
	crosslinkIntfs          []*routerIntf
	disabled                bool
	extendedKeys            map[string]string
	filterOnly              []net.IPNet
	generalPermit           []*proto
	natDomains              []*natDomain
	needProtect             bool
	noGroupCode             bool
	noInAcl                 *routerIntf
	noSecondaryOpt          map[*network]bool
	hardware                []*hardware
	origHardware            []*hardware
	origRouter              *router
	policyDistributionPoint *host
	primaryMark             int
	radiusAttributes        map[string]string
	routingOnly             bool
	secondaryMark           int
	trustPoint              string
	ipvMembers              []*router
	vrfMembers              []*router
	aclList                 []*aclInfo
	vrf                     string

	// This represents the router itself and is distinct from each real zone.
	zone *zone
}

func (x router) String() string { return x.name }

type routerIntf struct {
	netObj
	pathStoreData
	router          *router
	crypto          *crypto
	dhcpClient      bool
	dhcpServer      bool
	hub             []*crypto
	spoke           *crypto
	id              string
	isHub           bool
	isManagedHost   bool
	hardware        *hardware
	layer3Intf      *routerIntf
	loop            *loop
	loopback        bool
	loopEntryZone   map[pathStore]pathStore
	loopZoneBorder  bool
	mainIntf        *routerIntf
	natSet          natSet
	origMain        *routerIntf
	pathRestrict    []*pathRestriction
	peer            *routerIntf
	peerNetworks    netList
	realIntf        *routerIntf
	redundancyIntfs []*routerIntf
	redundancyType  string
	redundant       bool
	reroutePermit   []someObj
	reroutePermitNames []*parsedObjRef
	routeInZone     map[*network]intfList
	routes          map[*routerIntf]netMap
	routing         *routing
	rules           ruleList
	intfRules       ruleList
	outRules        ruleList
	idRules         map[string]*idIntf
	toZone1         pathObj
	zone            *zone
}

type intfList []*routerIntf

func (a *intfList) push(e *routerIntf) {
	*a = append(*a, e)
}

type idIntf struct {
	*routerIntf
	src *subnet
}

type owner struct {
	name    string
	isUsed  bool
	showAll bool
}

type routing struct {
	name  string
	prt   *proto
	mcast mcastInfo
}

type xxrp struct {
	prt   *proto
	mcast mcastInfo
}

type hardware struct {
	interfaces []*routerIntf
	crosslink  bool
	loopback   bool
	name       string
	natSet     natSet
	dstNatSet  natSet
	needOutAcl bool
	noInAcl    bool
	rules      ruleList
	intfRules  ruleList
	outRules   ruleList
	ioRules    map[string]ruleList
	subcmd     []string
}

type pathRestriction struct {
	activePath bool
}

type crypto struct {
	detailedCryptoAcl bool
	ipsec             *ipsec
	name              string
	tunnels           netList
}
type ipsec struct {
	name              string
	isakmp            *isakmp
	lifetime          *[2]int
	ah                string
	espAuthentication string
	espEncryption     string
	pfsGroup          string
}
type isakmp struct {
	name           string
	authentication string
	encryption     string
	group          string
	hash           string
	trustPoint     string
	ikeVersion     int
	lifetime       int
	natTraversal   string
}

type ipmask struct {
	ip   string // from string(net.IP)
	mask string // from string(net.IPMask)
}

type zone struct {
	ipVxObj
	privateObj
	pathStoreData
	pathObjData
	name                 string
	networks             netList
	attr                 map[string]string
	hasIdHosts           bool
	hasSecondary         bool
	hasNonPrimary        bool
	inArea               *area
	ipmask2aggregate     map[ipmask]*network
	ipmask2net           map[ipmask]netList
	isTunnel             bool
	loopback             bool
	natDomain            *natDomain
	noCheckSupernetRules bool
	partition            string
	primaryMark          int
	secondaryMark        int
	statefulMark         int
	unmanagedRouters     []*router
	watchingOwners       []*owner
	zoneCluster          []*zone
}

func (x zone) String() string { return x.name }

type routerAttributes struct {
	ownedObj
	name string
}

type area struct {
	disabledObj
	ownedObj
	privateObj
	ipVxObj
	usedObj
	name             string
	attr             map[string]string
	border           []*routerIntf
	inArea           *area
	managedRouters   []*router
	routerAttributes *routerAttributes
	watchingOwner    *owner
	zones            []*zone
}

func (x area) String() string { return x.name }

type natDomain struct {
	name    string
	natSet  natSet
	routers []*router
	zones   []*zone
}

type modifiers struct {
	reversed             bool
	stateless            bool
	oneway               bool
	srcNet               bool
	dstNet               bool
	overlaps             bool
	noCheckSupernetRules bool
}

type proto struct {
	name            string
	proto           string
	icmpType        int
	icmpCode        int
	modifiers       *modifiers
	src             *proto
	dst             *proto
	main            *proto
	split           *[2]*proto
	srcDstRangeList []*complexProto
	ports           [2]int
	established     bool
	statelessICMP   bool
	up              *proto
	localUp         *proto
	hasNeighbor     bool
	isUsed          bool
	printed         string
}
type protoList []*proto

func (l *protoList) push(p *proto) {
	*l = append(*l, p)
}

type complexProto struct {
	src  *proto
	dst  *proto
	orig *proto
}

type protoOrName interface{}

type protoGroup struct {
	name      string
	pairs     []protoOrName
	elements  protoList
	recursive bool
	isUsed    bool
}

type protoLookup struct {
	ip    *proto
	icmp  map[string]*proto
	tcp   map[string]*proto
	udp   map[string]*proto
	proto map[string]*proto
}

type objGroup struct {
	privateObj
	usedObj
	elements        []*parsedObjRef
	expandedClean   groupObjList
	expandedNoClean groupObjList
	ipVxObj
	name      string
	recursive bool
}

func (x objGroup) isDisabled() bool { return false }
func (x objGroup) String() string   { return x.name }

type service struct {
	ipVxObj
	privateObj
	name                       string
	disabled                   bool
	foreach                    bool
	rules                      []*unexpRule
	ruleCount                  int
	duplicateCount             int
	redundantCount             int
	hasSameDupl                map[*service]bool
	hasUnenforceable           bool
	hasUnenforceableRestricted bool
	multiOwner                 bool
	overlaps                   []*service
	overlapsUsed               map[*service]bool
	overlapsRestricted         bool
	owners                     []*owner
	seenEnforceable            bool
	seenUnenforceable          map[objPair]bool
	silentUnenforceable        bool
	subOwner                   *owner
	unknownOwner               bool
	user                       []*parsedObjRef
	expandedUser               groupObjList
}

func (x *service) String() string { return x.name }

type unexpRule struct {
	hasUser string
	action  string
	dst     []*parsedObjRef
	log     string
	prt     []protoOrName
	src     []*parsedObjRef
	service *service
}

type serviceRule struct {
	deny                 bool
	src                  []srvObj
	dst                  []srvObj
	prt                  protoList
	srcRange             *proto
	log                  string
	srcNet               bool
	dstNet               bool
	reversed             bool
	rule                 *unexpRule
	stateless            bool
	statelessICMP        bool
	noCheckSupernetRules bool
	oneway               bool
	overlaps             bool
	zone2netMap          map[*zone]map[*network]bool
}

type serviceRuleList []*serviceRule

func (a *serviceRuleList) push(e *serviceRule) {
	*a = append(*a, e)
}

type serviceRules struct {
	permit serviceRuleList
	deny   serviceRuleList
}

type groupedRule struct {
	*serviceRule
	src              []someObj
	dst              []someObj
	srcPath          pathStore
	dstPath          pathStore
	someNonSecondary bool
	somePrimary      bool
}
type ruleList []*groupedRule

func newRule(src, dst []someObj, prt []*proto) *groupedRule {
	return &groupedRule{
		src: src, dst: dst, serviceRule: &serviceRule{prt: prt}}
}

type pathRules struct {
	permit ruleList
	deny   ruleList
}

type mcastInfo struct {
	v4 []string
	v6 []string
}

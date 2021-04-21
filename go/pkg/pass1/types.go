package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"inet.af/netaddr"
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
	net netaddr.IPPrefix
}

type userInfo struct {
	elements groupObjList
	used     bool
}

type netOrRouter interface{}

type autoIntf struct {
	usedObj
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

type groupObj interface {
	isDisabled() bool
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
	getAttr(attr attrKey) attrVal
	getNetwork() *network
	getUsed() bool
	setUsed()
}
type srvObjList []srvObj

func (a *srvObjList) push(e srvObj) {
	*a = append(*a, e)
}

type someObj interface {
	String() string
	getNetwork() *network
	getUp() someObj
	address(m natMap) netaddr.IPPrefix
	getAttr(attr attrKey) attrVal
	getPathNode() pathStore
	getZone() pathObj
}

type withStdAddr struct {
	stdAddr string
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

type ipVxObj struct {
	ipV6 bool
}

func (x *ipVxObj) isIPv6() bool { return x.ipV6 }

type usedObj struct {
	isUsed bool
}

func (x *usedObj) getUsed() bool { return x.isUsed }
func (x *usedObj) setUsed()      { x.isUsed = true }

type ownerer interface {
	getOwner() *owner
	setOwner(o *owner)
}

const (
	hasIP = iota
	negotiatedIP
	bridgedIP
	shortIP
	tunnelIP
	unnumberedIP
)

type ipObj struct {
	disabledObj
	ipVxObj
	ownedObj
	usedObj
	name string
}

func (x ipObj) String() string { return x.name }

type natTagMap map[string]*network

type network struct {
	ipObj
	withStdAddr
	attr                 attrStore
	certId               string
	crosslink            bool
	descr                string
	dynamic              bool
	filterAt             map[int]bool
	hasIdHosts           bool
	hasOtherSubnet       bool
	hasSubnets           bool
	hidden               bool
	hosts                []*host
	identity             bool
	interfaces           intfList
	invisible            bool
	ipp                  netaddr.IPPrefix
	ipType               int
	isAggregate          bool
	isLayer3             bool
	link                 *network
	loopback             bool
	maxRoutingNet        *network
	maxSecondaryNet      *network
	nat                  map[string]*network
	natTag               string
	networks             netList
	noCheckSupernetRules bool
	partition            string
	radiusAttributes     map[string]string
	subnetOf             *network
	subnets              []*subnet
	unstableNat          map[*natDomain]netList
	up                   *network
	zone                 *zone
}

func (x *network) getNetwork() *network { return x }
func (x *network) getUp() someObj {
	if x.up == nil {
		return nil
	}
	return x.up
}
func (x *network) intfList() intfList { return x.interfaces }

type netList []*network

func (a *netList) push(e *network) {
	*a = append(*a, e)
}

type netObj struct {
	ipObj
	usedObj
	nat     map[string]netaddr.IP
	network *network
	up      someObj
}

func (x *netObj) getNetwork() *network { return x.network }
func (x *netObj) getUp() someObj       { return x.up }

type subnet struct {
	netObj
	withStdAddr
	hasNeighbor      bool
	id               string
	ldapId           string
	neighbor         *subnet
	ipp              netaddr.IPPrefix
	radiusAttributes map[string]string
}

type host struct {
	netObj
	id               string
	ip               netaddr.IP
	ipRange          netaddr.IPRange
	ldapId           string
	radiusAttributes map[string]string
	subnets          []*subnet
}

type model struct {
	commentChar      string
	class            string
	crypto           string
	doAuth           bool
	aclUseRealIP     bool
	canDynCrypto     bool
	canLogDeny       bool
	canObjectgroup   bool
	canVRF           bool
	cryptoInContext  bool
	filter           string
	hasIoACL         bool
	hasOutACL        bool
	inversedACLMask  bool
	logModifiers     map[string]string
	name             string
	needACL          bool
	needProtect      bool
	noFilterICMPCode bool
	noCryptoFilter   bool
	printRouterIntf  bool
	routing          string
	stateless        bool
	statelessSelf    bool
	statelessICMP    bool
	usePrefix        bool
}

type natSet map[string]bool

type natMap map[*network]*network

type aclInfo struct {
	name         string
	natMap       natMap
	rules        ruleList
	intfRules    ruleList
	protectSelf  bool
	addPermit    bool
	addDeny      bool
	filterAnySrc bool
	isStdACL     bool
	isCryptoACL  bool
	needProtect  []netaddr.IPPrefix
	subAclList   aclList
}

type aclList []*aclInfo

func (a *aclList) push(e *aclInfo) { *a = append(*a, e) }

type router struct {
	ipVxObj
	ownedObj
	usedObj
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
	origIntfs               intfList
	crosslinkIntfs          intfList
	disabled                bool
	extendedKeys            map[string]string
	filterOnly              []netaddr.IPPrefix
	generalPermit           []*proto
	natDomains              []*natDomain
	natTags                 map[*natDomain]stringList
	natSet                  natSet // Only used if aclUseRealIp
	natMap                  natMap // Only used if aclUseRealIp
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
	aclList                 aclList
	vrf                     string
}

func (x router) String() string { return x.name }

type loop struct {
	exit        pathObj
	distance    int
	clusterExit pathObj
	redirect    *loop
}

type routerIntf struct {
	netObj
	pathStoreData
	withStdAddr
	router          *router
	bindNat         []string
	dhcpClient      bool
	dhcpServer      bool
	hub             []*crypto
	spoke           *crypto
	id              string
	ip              netaddr.IP
	ipType          int
	isHub           bool
	isLayer3        bool
	hardware        *hardware
	layer3Intf      *routerIntf
	loop            *loop
	loopback        bool
	loopEntryZone   map[pathStore]pathStore
	loopZoneBorder  bool
	mainIntf        *routerIntf
	natMap          natMap
	noCheck         bool
	noInAcl         bool
	origMain        *routerIntf
	pathRestrict    []*pathRestriction
	peer            *routerIntf
	peerNetworks    netList
	realIntf        *routerIntf
	redundancyId    string
	redundancyIntfs intfList
	redundancyType  *mcastProto
	redundant       bool
	reroutePermit   netList
	routeInZone     map[*network]*routerIntf
	routes          map[*network]intfList
	routing         *mcastProto
	rules           ruleList
	splitOther      *routerIntf
	intfRules       ruleList
	outRules        ruleList
	idRules         map[string]*idIntf
	toZone1         pathObj
	zone            *zone
}

func (intf *routerIntf) getCrypto() *crypto {
	if intf.isHub {
		return intf.peer.realIntf.spoke
	}
	return intf.realIntf.spoke
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
	admins              stringList
	extendedBy          []*owner
	hideFromOuterOwners bool
	isUsed              bool
	name                string
	onlyWatch           bool
	showAll             bool
	showHiddenOwners    bool
	watchers            stringList
}

func (x owner) String() string { return x.name }

type mcastProto struct {
	name string
	prt  *proto
	mcast
}

type mcast struct {
	v4 multicast
	v6 multicast
}

type multicast struct {
	ips      []string
	networks []*network
}

type hardware struct {
	interfaces intfList
	crosslink  bool
	loopback   bool
	name       string
	bindNat    []string
	natMap     natMap
	needOutAcl bool
	noInAcl    bool
	rules      ruleList
	intfRules  ruleList
	outRules   ruleList
	ioRules    map[string]ruleList
	subcmd     stringList
}

type pathRestriction struct {
	activePath bool
	elements   []*routerIntf
	name       string
}

type crypto struct {
	usedObj
	bindNat           []string
	detailedCryptoAcl bool
	ipsec             *ipsec
	name              string
	hub               *routerIntf
	tunnels           netList
}
type ipsec struct {
	usedObj
	name              string
	isakmp            *isakmp
	lifetime          *[2]int
	ah                string
	espAuthentication string
	espEncryption     string
	pfsGroup          string
}
type isakmp struct {
	usedObj
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

type zone struct {
	ipVxObj
	pathStoreData
	pathObjData
	name                 string
	networks             netList
	attr                 attrStore
	hasIdHosts           bool
	hasSecondary         bool
	hasNonPrimary        bool
	inArea               *area
	ipPrefix2aggregate   map[netaddr.IPPrefix]*network
	ipPrefix2net         map[netaddr.IPPrefix]netList
	nat                  map[string]*network
	natDomain            *natDomain
	noCheckSupernetRules bool
	partition            string
	primaryMark          int
	secondaryMark        int
	statefulMark         int
	watchingOwners       []*owner
	cluster              []*zone
}

func (x zone) String() string { return x.name }

type routerAttributes struct {
	ownedObj
	name                    string
	generalPermit           []*proto
	policyDistributionPoint *host
}

type area struct {
	disabledObj
	ownedObj
	ipVxObj
	usedObj
	name             string
	anchor           *network
	attr             attrStore
	inclusiveBorder  []*routerIntf
	border           []*routerIntf
	inArea           *area
	managedRouters   []*router
	nat              map[string]*network
	routerAttributes *routerAttributes
	watchingOwner    *owner
	zones            []*zone
}

func (x area) String() string { return x.name }

type natDomain struct {
	name    string
	natSet  natSet
	natMap  natMap
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
	srcRange             *proto
}

type proto struct {
	usedObj
	name          string
	proto         string
	icmpType      int
	icmpCode      int
	modifiers     *modifiers
	main          *proto
	split         *[2]*proto
	ports         [2]int
	established   bool
	statelessICMP bool
	up            *proto
	localUp       *proto
}
type protoList []*proto

func (l *protoList) push(p *proto) {
	*l = append(*l, p)
}

type protoGroup struct {
	usedObj
	name      string
	list      stringList
	elements  protoList
	recursive bool
}

type objGroup struct {
	usedObj
	elements        []ast.Element
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
	name                       string
	description                string
	disableAt                  string
	disabled                   bool
	foreach                    bool
	rules                      []*unexpRule
	ruleCount                  int
	duplicateCount             int
	redundantCount             int
	hasSameDupl                map[*service]bool
	hasUnenforceable           bool
	hasUnenforceableRestricted bool
	identicalBody              []*service
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
	user                       []ast.Element
	expandedUser               groupObjList
}

func (x *service) String() string { return x.name }

type unexpRule struct {
	hasUser string
	action  string
	dst     []ast.Element
	log     string
	prt     protoList
	src     []ast.Element
	service *service
}

type serviceRule struct {
	modifiers
	deny          bool
	src           []srvObj
	dst           []srvObj
	prt           protoList
	log           string
	rule          *unexpRule
	statelessICMP bool
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

func (l *ruleList) push(r *groupedRule) {
	*l = append(*l, r)
}

func newRule(src, dst []someObj, prt []*proto) *groupedRule {
	return &groupedRule{
		src: src, dst: dst, serviceRule: &serviceRule{prt: prt}}
}

type pathRules struct {
	permit ruleList
	deny   ruleList
}

//###################################################################
// Efficient path traversal.
//###################################################################

type pathStoreData struct {
	path      map[pathStore]*routerIntf
	path1     map[pathStore]*routerIntf
	loopEntry map[pathStore]pathStore
	loopExit  map[pathStore]pathStore
	loopPath  map[pathStore]*loopPath
}

type pathStore interface {
	String() string
	getPath() map[pathStore]*routerIntf
	getPath1() map[pathStore]*routerIntf
	getLoopEntry() map[pathStore]pathStore
	getLoopExit() map[pathStore]pathStore
	getLoopPath() map[pathStore]*loopPath
	setPath(pathStore, *routerIntf)
	setPath1(pathStore, *routerIntf)
	setLoopEntry(pathStore, pathStore)
	setLoopExit(pathStore, pathStore)
	setLoopPath(pathStore, *loopPath)
	getZone() pathObj
}

func (x *pathStoreData) getPath() map[pathStore]*routerIntf    { return x.path }
func (x *pathStoreData) getPath1() map[pathStore]*routerIntf   { return x.path1 }
func (x *pathStoreData) getLoopEntry() map[pathStore]pathStore { return x.loopEntry }
func (x *pathStoreData) getLoopExit() map[pathStore]pathStore  { return x.loopExit }
func (x *pathStoreData) getLoopPath() map[pathStore]*loopPath  { return x.loopPath }

func (x *pathStoreData) setPath(s pathStore, i *routerIntf) {
	if x.path == nil {
		x.path = make(map[pathStore]*routerIntf)
	}
	x.path[s] = i
}
func (x *pathStoreData) setPath1(s pathStore, i *routerIntf) {
	if x.path1 == nil {
		x.path1 = make(map[pathStore]*routerIntf)
	}
	x.path1[s] = i
}
func (x *pathStoreData) setLoopEntry(s pathStore, e pathStore) {
	if x.loopEntry == nil {
		x.loopEntry = make(map[pathStore]pathStore)
	}
	x.loopEntry[s] = e
}
func (x *routerIntf) setLoopEntryZone(s pathStore, e pathStore) {
	if x.loopEntryZone == nil {
		x.loopEntryZone = make(map[pathStore]pathStore)
	}
	x.loopEntryZone[s] = e
}
func (x *pathStoreData) setLoopExit(s pathStore, e pathStore) {
	if x.loopExit == nil {
		x.loopExit = make(map[pathStore]pathStore)
	}
	x.loopExit[s] = e
}
func (x *pathStoreData) setLoopPath(s pathStore, i *loopPath) {
	if x.loopPath == nil {
		x.loopPath = make(map[pathStore]*loopPath)
	}
	x.loopPath[s] = i
}

type pathObjData struct {
	interfaces intfList
	activePath bool
	distance   int
	loop       *loop
	navi       map[pathObj]navigation
	toZone1    *routerIntf
}

type pathObj interface {
	String() string
	intfList() intfList
	isActivePath() bool
	setActivePath()
	clearActivePath()
	setDistance(int)
	getDistance() int
	setLoop(*loop)
	getLoop() *loop
	getNavi() map[pathObj]navigation
	setNavi(pathObj, navigation)
	setToZone1(*routerIntf)
	getToZone1() *routerIntf
}

func (x *pathObjData) intfList() intfList              { return x.interfaces }
func (x *pathObjData) isActivePath() bool              { return x.activePath }
func (x *pathObjData) setActivePath()                  { x.activePath = true }
func (x *pathObjData) clearActivePath()                { x.activePath = false }
func (x *pathObjData) getDistance() int                { return x.distance }
func (x *pathObjData) setDistance(dist int)            { x.distance = dist }
func (x *pathObjData) getLoop() *loop                  { return x.loop }
func (x *pathObjData) getNavi() map[pathObj]navigation { return x.navi }
func (x *pathObjData) getToZone1() *routerIntf         { return x.toZone1 }

func (x *pathObjData) setLoop(newLoop *loop) {
	x.loop = newLoop
}

func (x *pathObjData) setNavi(o pathObj, n navigation) {
	if x.navi == nil {
		x.navi = make(map[pathObj]navigation)
	}
	x.navi[o] = n
}

func (x *pathObjData) setToZone1(intfToZone1 *routerIntf) {
	x.toZone1 = intfToZone1
}

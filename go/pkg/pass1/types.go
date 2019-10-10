package pass1

import (
	"fmt"
	"net"
)

type stringerList []fmt.Stringer

type Config struct {
	CheckDuplicateRules          string
	CheckRedundantRules          string
	CheckFullyRedundantRules     string
	CheckPolicyDistributionPoint string
	CheckSupernetRules           string
	CheckTransientSupernetRules  string
	CheckUnusedGroups            string
	CheckUnusedProtocols         string
	Verbose                      bool
	TimeStamps                   bool
	Pipe                         bool
	MaxErrors                    int
	autoDefaultRoute             bool
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

type ipObj struct {
	name       string
	ip         net.IP
	unnumbered bool
	negotiated bool
	short      bool
	tunnel     bool
	bridged    bool
	up         someObj
}

func (x ipObj) String() string { return x.name }

func (x *ipObj) getUp() someObj { return x.up }

type natMap map[string]*network

type network struct {
	ipObj
	attr             map[string]string
	mask             net.IPMask
	subnets          []*subnet
	hosts            []*host
	interfaces       []*routerIntf
	zone             *zone
	disabled         bool
	hasOtherSubnet   bool
	isAggregate      bool
	maxRoutingNet    *network
	maxSecondaryNet  *network
	nat              map[string]*network
	networks         netList
	dynamic          bool
	hidden           bool
	ipV6             bool
	natTag           string
	certId           string
	filterAt         map[int]bool
	hasIdHosts       bool
	invisible        bool
	radiusAttributes map[string]string
	up               *network
}

func (x *network) getNetwork() *network { return x }

type netList []*network

type netObj struct {
	ipObj
	network *network
}

func (x *netObj) getNetwork() *network { return x.network }

type subnet struct {
	netObj
	mask             net.IPMask
	nat              map[string]net.IP
	id               string
	ldapId           string
	radiusAttributes map[string]string
}

type host struct {
	netObj
	subnets []*subnet
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
	extendedKeys            map[string]string
	filterOnly              []net.IPNet
	generalPermit           []*proto
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
	ipV6                    bool
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
	hardware        *hardware
	layer3Intf      *routerIntf
	loop            *loop
	loopback        bool
	loopEntryZone   map[pathStore]pathStore
	loopZoneBorder  bool
	mainIntf        *routerIntf
	nat             map[string]net.IP
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

// Add element to slice.
func (a *intfList) push(e *routerIntf) {
	*a = append(*a, e)
}

type idIntf struct {
	*routerIntf
	src *subnet
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

type zone struct {
	pathStoreData
	pathObjData
	name                 string
	networks             netList
	attr                 map[string]string
	hasSecondary         bool
	hasNonPrimary        bool
	inArea               *area
	ipmask2aggregate     map[string]*network // Key: string(ip) + string(mask)
	ipmask2net           map[string]netList
	natDomain            *natDomain
	noCheckSupernetRules bool
	partition            string
	primaryMark          int
	secondaryMark        int
	statefulMark         int
	zoneCluster          []*zone
}

func (x zone) String() string { return x.name }

type area struct {
	name   string
	attr   map[string]string
	inArea *area
}

type natDomain struct {
	natSet natSet
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
	name        string
	proto       string
	icmpType    int
	icmpCode    int
	modifiers   modifiers
	src         *proto
	dst         *proto
	main        *proto
	ports       [2]int
	established bool
	up          *proto
	localUp     *proto
	hasNeighbor bool
	isUsed      bool
	printed     string
}
type protoList []*proto

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
	name     string
	elements []someObj
	isUsed   bool
}

type service struct {
	name               string
	disabled           bool
	ruleCount          int
	duplicateCount     int
	redundantCount     int
	hasSameDupl        map[*service]bool
	overlaps           []*service
	overlapsUsed       map[*service]bool
	overlapsRestricted bool
}

type unexpRule struct {
	prt     []protoOrName
	service *service
}

type serviceRule struct {
	deny                 bool
	src                  []someObj
	dst                  []someObj
	prt                  protoList
	srcRange             *proto
	log                  string
	rule                 *unexpRule
	stateless            bool
	statelessICMP        bool
	noCheckSupernetRules bool
	oneway               bool
	overlaps             bool
	zone2netMap          map[*zone]map[*network]bool
}

type serviceRuleList []*serviceRule

type serviceRules struct {
	permit serviceRuleList
	deny   serviceRuleList
}

type groupedRule struct {
	serviceRule
	srcPath          pathStore
	dstPath          pathStore
	someNonSecondary bool
	somePrimary      bool
}
type ruleList []*groupedRule

func newRule(src, dst []someObj, prt []*proto) *groupedRule {
	return &groupedRule{
		serviceRule: serviceRule{src: src, dst: dst, prt: prt}}
}

type pathRules struct {
	permit ruleList
	deny   ruleList
}

type mcastInfo struct {
	v4 []string
	v6 []string
}

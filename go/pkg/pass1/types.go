package pass1

import (
	"net"
)

type Config struct {
	CheckDuplicateRules      string
	CheckRedundantRules      string
	CheckFullyRedundantRules string
	Verbose                  bool
	TimeStamps               bool
	Pipe                     bool
	MaxErrors                int
	autoDefaultRoute         bool
}

type someObj interface {
	getName() string
	getNetwork() *network
	getUp() someObj
	address(nn natSet) net.IPNet
	getAttr(attr string) string
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

func (x *ipObj) getName() string { return x.name }
func (x *ipObj) getUp() someObj  { return x.up }

type natMap map[string]*network

type network struct {
	ipObj
	attr             map[string]string
	mask             net.IPMask
	subnets          []*subnet
	interfaces       []*routerIntf
	zone             *zone
	hasOtherSubnet   bool
	maxSecondaryNet  *network
	nat              map[string]*network
	dynamic          bool
	hidden           bool
	ipV6             bool
	natTag           string
	certId           string
	filterAt         map[int]bool
	hasIdHosts       bool
	radiusAttributes map[string]string
}

func (x *network) getNetwork() *network { return x }

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

type model struct {
	CommentChar     string
	Class           string
	crypto          string
	DoAuth          bool
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
	name             string
	deviceName       string
	managed          string
	semiManaged      bool
	adminIP          []string
	model            *model
	log              map[string]string
	logDeny          bool
	localMark        int
	origIntfs        []*routerIntf
	crosslinkIntfs   []*routerIntf
	filterOnly       []net.IPNet
	generalPermit    []*proto
	needProtect      bool
	noGroupCode      bool
	noSecondaryOpt   map[*network]bool
	hardware         []*hardware
	origHardware     []*hardware
	origRouter       *router
	primaryMark      int
	radiusAttributes map[string]string
	routingOnly      bool
	secondaryMark    int
	trustPoint       string
	vrfMembers       []*router
	ipV6             bool
	aclList          []*aclInfo
	vrf              string
}

func (x *router) getName() string { return x.name }

type routerIntf struct {
	netObj
	pathStoreData
	router         *router
	crypto         *crypto
	dhcpClient     bool
	dhcpServer     bool
	hub            []*crypto
	spoke          *crypto
	id             string
	isHub          bool
	hardware       *hardware
	loop           *loop
	loopback       bool
	loopEntryZone  map[pathStore]pathStore
	loopZoneBorder bool
	mainIntf       *routerIntf
	nat            map[string]net.IP
	natSet         natSet
	origMain       *routerIntf
	pathRestrict   []*pathRestriction
	//	reachableAt   map[pathObj][]int
	peer            *routerIntf
	peerNetworks    []*network
	realIntf        *routerIntf
	redundancyIntfs []*routerIntf
	redundancyType  string
	redundant       bool
	reroutePermit   []someObj
	routes          map[*routerIntf]map[*network]bool
	routing         *routing
	rules           ruleList
	intfRules       ruleList
	outRules        ruleList
	idRules         map[string]*idIntf
	toZone1         pathObj
	zone            *zone
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
	ipsec             *ipsec
	detailedCryptoAcl bool
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
}

type zone struct {
	pathStoreData
	pathObjData
	name          string
	networks      []*network
	attr          map[string]string
	hasSecondary  bool
	hasNonPrimary bool
	inArea        *area
	natDomain     *natDomain
	partition     string
	primaryMark   int
	secondaryMark int
	zoneCluster   []*zone
}

func (x *zone) getName() string { return x.name }

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

type groupedRule struct {
	deny             bool
	src              []someObj
	dst              []someObj
	prt              protoList
	srcRange         *proto
	log              string
	rule             *unexpRule
	srcPath          pathStore
	dstPath          pathStore
	stateless        bool
	statelessICMP    bool
	overlaps         bool
	someNonSecondary bool
	somePrimary      bool
}
type ruleList []*groupedRule

type pathRules struct {
	permit ruleList
	deny   ruleList
}

type protoOrName interface{}
type protoList []*proto

type protoGroup struct {
	pairs     []protoOrName
	elements  protoList
	recursive bool
	isUsed    bool
}

type mcastInfo struct {
	v4 []string
	v6 []string
}

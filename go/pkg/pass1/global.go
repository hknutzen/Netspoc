package pass1

import ()

var (
	version string

	ErrorCounter int

	prtAh               *proto
	prtBootpc           *proto
	prtBootps           *proto
	prtEsp              *proto
	prtIP               *proto
	prtIke              *proto
	prtNatt             *proto
	prtUDP              *proto
	rangeTCPEstablished *proto

	knownLog map[string]bool
	xxrpInfo map[string]*xxrp

	aggregates       map[string]*network
	areas            map[string]*area
	cryptoMap        map[string]*crypto
	groups           map[string]*objGroup
	hosts            map[string]*host
	interfaces       map[string]*routerIntf
	ipsecMap         map[string]*ipsec
	isakmpMap        map[string]*isakmp
	networks         map[string]*network
	owners           map[string]*owner
	pathrestrictions map[string]*pathRestriction
	protocols        map[string]*proto
	protocolGroups   map[string]*protoGroup
	routers          map[string]*router
	routers6         map[string]*router
	services         map[string]*service

	prtMap  protoLookup
	pRules  pathRules
	sRules  = new(serviceRules)
	userObj userInfo

	allNetworks        netList
	ascendingAreas     []*area
	managedRouters     []*router
	routingOnlyRouters []*router
	zones              []*zone

	InPath string
	OutDir string
)

const (
	noAttr = iota
	ownAttr
	groupPolicy
	tgGeneral
)

var asaVpnAttributes = map[string]int{

	// Our own attributes
	"check-subject-name":       ownAttr,
	"check-extended-key-usage": ownAttr,
	"trust-point":              ownAttr,

	// group-policy attributes
	"anyconnect-custom_perapp": groupPolicy,
	"banner":                   groupPolicy,
	"dns-server":               groupPolicy,
	"default-domain":           groupPolicy,
	"split-dns":                groupPolicy,
	"wins-server":              groupPolicy,
	"vpn-access-hours":         groupPolicy,
	"vpn-idle-timeout":         groupPolicy,
	"vpn-session-timeout":      groupPolicy,
	"vpn-simultaneous-logins":  groupPolicy,
	"vlan":                     groupPolicy,
	"split-tunnel-policy":      groupPolicy,

	// tunnel-group general-attributes
	"authentication-server-group":                 tgGeneral,
	"authorization-server-group":                  tgGeneral,
	"authorization-required":                      tgGeneral,
	"username-from-certificate":                   tgGeneral,
	"password-management_password-expire-in-days": tgGeneral,
}

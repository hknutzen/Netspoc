package pass1

import ()

var (
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

	knownLog = make(map[string]bool)

	services map[string]*service

	pRules  pathRules
	sRules  = new(serviceRules)
	userObj userInfo

	allNetworks        netList
	ascendingAreas     []*area
	allRouters         []*router
	managedRouters     []*router
	routerFragments    []*router
	routingOnlyRouters []*router
	virtualInterfaces  intfList
	zones              []*zone

//	InPath string
//	OutDir string
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

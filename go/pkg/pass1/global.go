package pass1

import ()

var (
	version string

	ErrorCounter int

	// will become local variable when conversion to Go is finished
	NATDomains     []*natDomain
	NATTag2natType map[string]string

	prtAh               *proto
	prtBootpc           *proto
	prtBootps           *proto
	prtEsp              *proto
	prtIP               *proto
	prtIke              *proto
	prtNatt             *proto
	prtUDP              *proto
	rangeTCPEstablished *proto

	xxrpInfo map[string]*xxrp

	cryptoMap      map[string]*crypto
	groups         map[string]*objGroup
	protocols      map[string]*proto
	protocolGroups map[string]*protoGroup
	routers        map[string]*router
	routers6       map[string]*router
	services       map[string]*service

	prtMap protoLookup
	pRules pathRules
	sRules *serviceRules

	allNetworks        netList
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
	"authentication-server-group": tgGeneral,
	"authorization-server-group":  tgGeneral,
	"authorization-required":      tgGeneral,
	"username-from-certificate":   tgGeneral,
}

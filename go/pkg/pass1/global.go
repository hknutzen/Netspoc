package pass1

import (
	"time"
)

var (
	version string

	config Config

	startTime    time.Time
	ErrorCounter int

	prtIP               *proto
	prtBootps           *proto
	prtBootpc           *proto
	prtUDP              *proto
	rangeTCPEstablished *proto

	xxrpInfo map[string]*xxrp

	protocols      map[string]*proto
	protocolgroups map[string]*protoGroup
	routers        map[string]*router
	routers6       map[string]*router
	services       map[string]*service

	pRules *pathRules
	sRules *serviceRules

	managedRouters     []*router
	routingOnlyRouters []*router
	zones              []*zone

	OutDir string
)

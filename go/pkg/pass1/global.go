package pass1

import (
	"time"
)

var version string

var config Config

var startTime time.Time
var ErrorCounter int

var prtIP *proto
var prtBootps *proto
var prtBootpc *proto
var xxrpInfo map[string]*xxrp

var protocols map[string]*proto
var protocolgroups map[string]*protoGroup

var services map[string]*service

var pRules *pathRules

var managedRouters []*router
var routingOnlyRouters []*router
var zones []*zone

var outDir string

package pass1

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"time"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
)

var (
	program = "Netspoc"
	version = "devel"
)

type spoc struct {
	conf            *conf.Config
	startTime       time.Time
	toStderr        func(string)
	errCount        int
	initialErrCount int
	messages        stringList
	aborted         bool
	showDiag        bool
	// State of compiler
	symTable              *symbolTable
	userObj               userInfo
	allNetworks           netList
	allRouters            []*router
	managedRouters        []*router
	allPathRules          pathRules
	allZones              []*zone
	ascendingServices     []*service
	ascendingAreas        []*area
	pathrestrictions      []*pathRestriction
	prt                   *stdProto
	network00             *network
	network00v6           *network
	border2obj2auto       map[*routerIntf]map[netOrRouter]intfList
	routerAutoInterfaces  map[*router]*autoIntf
	networkAutoInterfaces map[networkAutoIntfKey]*autoIntf
}

func initSpoc(d oslink.Data, cnf *conf.Config) *spoc {
	c := &spoc{
		conf:                  cnf,
		startTime:             time.Now(),
		toStderr:              func(s string) { fmt.Fprintln(d.Stderr, s) },
		showDiag:              d.ShowDiag,
		routerAutoInterfaces:  make(map[*router]*autoIntf),
		networkAutoInterfaces: make(map[networkAutoIntfKey]*autoIntf),
		network00: &network{
			ipObj:          ipObj{name: "network:0/0"},
			ipp:            netip.PrefixFrom(getZeroIp(false), 0),
			withStdAddr:    withStdAddr{stdAddr: "0.0.0.0/0"},
			isAggregate:    true,
			hasOtherSubnet: true,
		},
		network00v6: &network{
			ipObj:          ipObj{name: "network:0/0"},
			ipp:            netip.PrefixFrom(getZeroIp(true), 0),
			withStdAddr:    withStdAddr{stdAddr: "::/0"},
			isAggregate:    true,
			hasOtherSubnet: true,
		},
	}
	return c
}

type bailout struct{}

func (c *spoc) terminate() {
	c.aborted = true
	panic(bailout{})
}

func handleBailout(f, cleanup func()) {
	defer func() {
		if e := recover(); e != nil {
			if _, ok := e.(bailout); !ok {
				panic(e) // Resume same panic if it's not a bailout.
			}
		}
		cleanup()
	}()
	f()
}

func (c *spoc) toStderrf(format string, args ...interface{}) {
	c.toStderr(fmt.Sprintf(format, args...))
}

func (c *spoc) abort(format string, args ...interface{}) {
	c.toStderrf("Error: "+format, args...)
	c.toStderr("Aborted")
	c.errCount++
	c.terminate()
}

func (c *spoc) stopOnErr() {
	if c.errCount > 0 {
		c.toStderrf("Aborted with %d error(s)", c.errCount)
		c.terminate()
	}
}

func (c *spoc) err(format string, args ...interface{}) {
	msg := fmt.Sprintf("Error: "+format, args...)
	c.errCount++
	c.toStderr(msg)
	if c.errCount >= c.conf.MaxErrors {
		c.toStderrf("Aborted after %d errors", c.errCount)
		c.terminate()
	}
}

func (c *spoc) warn(format string, args ...interface{}) {
	c.toStderrf("Warning: "+format, args...)
}

func (c *spoc) warnOrErr(
	errType conf.TriState, format string, args ...interface{}) {

	if errType == "warn" {
		c.warn(format, args...)
	} else {
		c.err(format, args...)
	}
}

func (c *spoc) uselessSvcAttr(attr string, svc *service) {
	if errType := c.conf.CheckServiceUselessAttribute; errType != "" {
		c.warnOrErr(errType, "Useless '%s' at %s", attr, svc)
	}
}

func (c *spoc) info(format string, args ...interface{}) {
	if !c.conf.Quiet {
		c.toStderrf(format, args...)
	}
}

func (c *spoc) progress(msg string) {
	if !c.conf.Quiet {
		if c.conf.TimeStamps {
			msg =
				fmt.Sprintf("%.0fs %s", time.Since(c.startTime).Seconds(), msg)
		}
		c.toStderr(msg)
	}
}

func (c *spoc) diag(format string, args ...interface{}) {
	if c.showDiag {
		c.toStderrf("DIAG: "+format, args...)
	}
}

func (c *spoc) bufferedSpoc() *spoc {
	c2 := *c
	c2.initialErrCount = c2.errCount
	c2.messages = make(stringList, 0)
	c2.toStderr = func(s string) { c2.messages.push(s) }
	return &c2
}

func (c *spoc) sendBuf(c2 *spoc) {
	for _, msg := range c2.messages {
		c.toStderr(msg)
	}
	c.errCount += c2.errCount - c2.initialErrCount

	if c2.aborted {
		c.terminate()
	}
}

// Sort error messages before output.
func (c *spoc) sortedSpoc(f func(*spoc)) {
	c2 := c.bufferedSpoc()
	handleBailout(
		func() { f(c2) },
		func() {
			// Leave "Abort" message as last message.
			l := len(c2.messages)
			if c2.aborted {
				l--
			}
			sort.Strings(c2.messages[:l])
			c.sendBuf(c2)
		})
}

func toplevelSpoc(
	d oslink.Data, conf *conf.Config, f func(*spoc)) (errCount int) {

	c := initSpoc(d, conf)
	handleBailout(
		func() { f(c) },
		func() { errCount = c.errCount })
	return
}

func SpocMain(d oslink.Data) int {
	inDir, outDir, cnf, abort := conf.GetArgs(d)
	if abort {
		fmt.Fprintln(d.Stderr, "Aborted")
		return 1
	}
	return toplevelSpoc(d, cnf, func(c *spoc) {
		if device := c.conf.DebugPass2; device != "" {
			pass2.File(device, outDir, path.Join(outDir, ".prev"))
			return
		}
		c.info(program + ", version " + version)
		c.readNetspoc(inDir)
		c.showReadStatistics()
		c.orderProtocols()
		c.checkIPAddresses()
		c.setZone()
		c.setPath()
		NATDomains, _, _ := c.distributeNatInfo()
		sRules := c.normalizeServices()
		c.stopOnErr()
		pRules, dRules := c.convertHostsInRules(sRules)
		c.groupPathRules(pRules, dRules)

		c.startWithBackground(
			func(c *spoc) {
				c.findSubnetsInNatDomain(NATDomains)
				c.checkUnstableNatRules()
				c.markManagedLocal()
				c.checkDynamicNatRules()
				c.checkSupernetRules(pRules)
			},
			func(c *spoc) {
				c.checkServiceOwner(sRules)
				c.checkIdenticalServices(sRules)
				c.checkUnused()
				c.checkRedundantRules()
			})

		c.removeSimpleDuplicateRules()
		c.combineSubnetsInRules()
		c.setPolicyDistributionIP()
		c.expandCrypto()
		c.findActiveRoutes()
		c.genReverseRules()
		if outDir != "" {
			c.markSecondaryRules()
			c.rulesDistribution()
			c.printCode(outDir)
			c.copyRaw(inDir, outDir)
		}
		c.stopOnErr()
		c.progress("Finished")
	})
}

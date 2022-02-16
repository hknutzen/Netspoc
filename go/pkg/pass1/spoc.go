package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
	"os"
	"path"
	"sort"
	"time"
)

var (
	program = "Netspoc"
	version = "devel"
)

const (
	abortM = iota
	errM
	warnM
	infoM
	progressM
	diagM
	checkErrM
)

type spoc struct {
	toStderr        func(string)
	errCount        int
	initialErrCount int
	messages        stringList
	aborted         bool
	// State of compiler
	userObj               userInfo
	allNetworks           netList
	allRouters            []*router
	managedRouters        []*router
	allPathRules          pathRules
	allZones              []*zone
	ascendingServices     []*service
	ascendingAreas        []*area
	pathrestrictions      []*pathRestriction
	virtualInterfaces     intfList
	prt                   *stdProto
	border2obj2auto       map[*routerIntf]map[netOrRouter]intfList
	routerAutoInterfaces  map[*router]*autoIntf
	networkAutoInterfaces map[networkAutoIntfKey]*autoIntf
}

func initSpoc() *spoc {
	c := &spoc{
		toStderr:              func(s string) { fmt.Fprintln(os.Stderr, s) },
		routerAutoInterfaces:  make(map[*router]*autoIntf),
		networkAutoInterfaces: make(map[networkAutoIntfKey]*autoIntf),
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
	return
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
	if c.errCount >= conf.Conf.MaxErrors {
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

func (c *spoc) info(format string, args ...interface{}) {
	if !conf.Conf.Quiet {
		c.toStderrf(format, args...)
	}
}

func (c *spoc) progress(msg string) {
	if !conf.Conf.Quiet {
		if conf.Conf.TimeStamps {
			msg =
				fmt.Sprintf("%.0fs %s", time.Since(conf.StartTime).Seconds(), msg)
		}
		c.toStderr(msg)
	}
}

func (c *spoc) diag(format string, args ...interface{}) {
	if os.Getenv("SHOW_DIAG") != "" {
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

func toplevelSpoc(f func(*spoc)) (errCount int) {
	c := initSpoc()
	handleBailout(
		func() { f(c) },
		func() { errCount = c.errCount })
	return
}

func SpocMain() (errCount int) {
	return toplevelSpoc(func(c *spoc) {
		inDir, outDir, abort := conf.GetArgs()
		if abort {
			c.toStderr("Aborted")
			c.errCount++
			c.terminate()
		}
		if device := conf.Conf.DebugPass2; device != "" {
			pass2.File(device, outDir, path.Join(outDir, ".prev"))
			return
		}
		c.info(program + ", version " + version)
		c.readNetspoc(inDir)
		c.showReadStatistics()
		c.orderProtocols()
		c.markDisabled()
		c.checkIPAddresses()
		c.setZone()
		c.setPath()
		NATDomains, NATTag2natType, _ := c.distributeNatInfo()
		sRules := c.normalizeServices()
		c.stopOnErr()
		c.checkServiceOwner(sRules)
		pRules, dRules := c.convertHostsInRules(sRules)
		c.groupPathRules(pRules, dRules)

		c2 := c.startInBackground(func(c *spoc) {
			c.checkIdenticalServices(sRules)
			c.checkUnused()
			c.checkRedundantRules()
		})
		c.findSubnetsInNatDomain(NATDomains)
		c.checkUnstableNatRules()
		c.markManagedLocal()
		c.checkDynamicNatRules(NATDomains, NATTag2natType)
		c.checkSupernetRules(pRules)
		c.collectMessages(c2)

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

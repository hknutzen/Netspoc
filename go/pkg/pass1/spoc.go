package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"os"
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
	// Collect messages.
	msgChan chan spocMsg
	// Report that all or some messages have been processed.
	ready chan bool
	// State of compiler
	userObj            userInfo
	allNetworks        netList
	allRouters         []*router
	managedRouters     []*router
	routingOnlyRouters []*router
	routerFragments    []*router
	allPathRules       pathRules
	allZones           []*zone
	ascendingAreas     []*area
	pathrestrictions   []*pathRestriction
	virtualInterfaces  intfList
	prt                *stdProto
}

func initSpoc() *spoc {
	c := &spoc{
		msgChan: make(chan spocMsg),
		ready:   make(chan bool),
	}
	return c
}

type spocMsg struct {
	typ  int
	text string
}

func (c *spoc) abort(format string, args ...interface{}) {
	t := fmt.Sprintf(format, args...)
	c.msgChan <- spocMsg{typ: abortM, text: t}
	// Wait until program has terminated.
	<-make(chan int)
}

func (c *spoc) stopOnErr() bool {
	c.msgChan <- spocMsg{typ: checkErrM}
	// Continue or wait until program has terminated if some error was seen.
	return <-c.ready
}

func (c *spoc) err(format string, args ...interface{}) {
	t := fmt.Sprintf(format, args...)
	c.msgChan <- spocMsg{typ: errM, text: t}
}

func (c *spoc) warn(format string, args ...interface{}) {
	t := fmt.Sprintf(format, args...)
	c.msgChan <- spocMsg{typ: warnM, text: t}
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
	if conf.Conf.Verbose {
		t := fmt.Sprintf(format, args...)
		c.msgChan <- spocMsg{typ: infoM, text: t}
	}
}

func (c *spoc) progress(msg string) {
	if conf.Conf.Verbose {
		if conf.Conf.TimeStamps {
			msg =
				fmt.Sprintf("%.0fs %s", time.Since(conf.StartTime).Seconds(), msg)
		}
		c.msgChan <- spocMsg{typ: progressM, text: msg}
	}
}

func (c *spoc) diag(format string, args ...interface{}) {
	if os.Getenv("SHOW_DIAG") != "" {
		t := fmt.Sprintf(format, args...)
		c.msgChan <- spocMsg{typ: diagM, text: t}
	}
}

func (c *spoc) printMessages() int {
	errCounter := 0
	for m := range c.msgChan {
		t := m.text
		switch m.typ {
		case abortM:
			fmt.Fprintln(os.Stderr, "Error: "+t)
			fmt.Fprintln(os.Stderr, "Aborted")
			errCounter++
			return errCounter
		case errM:
			fmt.Fprintln(os.Stderr, "Error: "+t)
			errCounter++
			if errCounter >= conf.Conf.MaxErrors {
				fmt.Fprintf(os.Stderr, "Aborted after %d errors\n", errCounter)
				return errCounter
			}
		case checkErrM:
			if errCounter > 0 {
				fmt.Fprintf(os.Stderr, "Aborted with %d error(s)\n", errCounter)
				return errCounter
			} else {
				c.ready <- true
			}
		case warnM:
			fmt.Fprintln(os.Stderr, "Warning: "+t)
		case diagM:
			fmt.Fprintln(os.Stderr, "DIAG: "+t)
		default:
			fmt.Fprintln(os.Stderr, t)
		}
	}
	return errCounter
}

func (c *spoc) sortingSpoc() *spoc {
	c2 := *c
	ch := make(chan spocMsg)
	c2.msgChan = ch
	go func() {
		var l []spocMsg
		for m := range ch {
			l = append(l, m)
		}
		sort.Slice(l, func(i, j int) bool {
			if l[i].typ == l[j].typ {
				return l[i].text < l[j].text
			}
			return l[i].typ < l[j].typ
		})
		for _, m := range l {
			c.msgChan <- m
		}
		c.ready <- true
	}()
	return &c2
}

func (c *spoc) finish() {
	close(c.msgChan)
	<-c.ready
}

func SpocMain() int {
	inDir, outDir := conf.GetArgs()
	diag.Info(program + ", version " + version)
	c := initSpoc()
	go func() {
		c.readNetspoc(inDir)
		c.showReadStatistics()
		c.orderProtocols()
		c.markDisabled()
		c.checkIPAdresses()
		c.setZone()
		c.setPath()
		NATDomains, NATTag2natType, _ := c.distributeNatInfo()
		c.findSubnetsInZone()
		sRules := c.normalizeServices()
		c.stopOnErr()
		c.checkServiceOwner(sRules)
		pRules, dRules := c.convertHostsInRules(sRules)
		c.groupPathRules(pRules, dRules)
		c.findSubnetsInNatDomain(NATDomains)
		c.checkUnstableNatRules()
		c.markManagedLocal()
		c.checkDynamicNatRules(NATDomains, NATTag2natType)
		c.checkUnusedGroups()
		c.checkSupernetRules(pRules)
		c.checkRedundantRules()
		c.removeSimpleDuplicateRules()
		c.combineSubnetsInRules()
		c.SetPolicyDistributionIP()
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
		c.progress("Finished pass1")
		close(c.msgChan)
	}()
	return c.printMessages()
}

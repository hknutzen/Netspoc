package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	program = "Netspoc"
	version = "devel"
)

const (
	abortM    = iota
	errM      = iota
	warnM     = iota
	infoM     = iota
	progressM = iota
	diagM     = iota
)

type spocMsg struct {
	typ  int
	text string
}

type spoc struct {
	msgChan   chan spocMsg
	waitGroup *sync.WaitGroup
}

func (c *spoc) abort(format string, args ...interface{}) {
	t := fmt.Sprintf(format, args...)
	c.msgChan <- spocMsg{typ: abortM, text: t}
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

func (c *spoc) printMessages() {
	c.waitGroup.Add(1)
	ch := c.msgChan
	for m := range ch {
		t := m.text
		switch m.typ {
		case abortM:
			abort.Msg(t)
		case errM:
			errMsg(t)
		case warnM:
			warnMsg(t)
		case diagM:
			diag.Msg(t)
		default:
			info(t)
		}
	}
	c.waitGroup.Done()
}

func (c *spoc) sortingSpoc() *spoc {
	c2 := *c
	ch := make(chan spocMsg)
	c2.msgChan = ch
	c2.waitGroup = new(sync.WaitGroup)
	c2.waitGroup.Add(1)
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
		c2.waitGroup.Done()
	}()
	return &c2
}

func startSpoc() *spoc {
	c := &spoc{msgChan: make(chan spocMsg), waitGroup: new(sync.WaitGroup)}
	go c.printMessages()
	return c
}

func (c *spoc) finish() {
	close(c.msgChan)
	c.waitGroup.Wait()
}

func SpocMain() {
	inDir, outDir := conf.GetArgs()
	diag.Info(program + ", version " + version)
	c := startSpoc()
	ReadNetspoc(inDir)
	ShowReadStatistics()
	OrderProtocols()
	MarkDisabled()
	CheckIPAdresses()
	SetZone()
	SetPath()
	NATDomains, NATTag2natType, _ := DistributeNatInfo()
	FindSubnetsInZone()
	NormalizeServices()
	AbortOnError()

	c.checkServiceOwner()
	pRules, dRules := c.convertHostsInRules()
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
	c.finish()
	AbortOnError()
	diag.Progress("Finished pass1")
}

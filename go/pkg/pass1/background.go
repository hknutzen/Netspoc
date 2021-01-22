package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"regexp"
)

type spocWait chan struct{}
type bgSpoc struct {
	*spoc
	ch spocWait
}

func (c *spoc) startInBackground(f func(*spoc)) bgSpoc {
	if conf.Conf.ConcurrencyPass1 <= 1 {
		f(c)
		return bgSpoc{}
	}
	// Channel is used to signal that background job has finished.
	ch := make(spocWait)
	c2 := c.bufferedSpoc()
	go func() {
		defer func() {
			if e := recover(); e != nil {
				if _, ok := e.(bailout); !ok {
					// resume same panic if it's not a bailout
					panic(e)
				}
			}
			close(ch)
		}()
		f(c2)
		if conf.Conf.TimeStamps {
			c2.progress("Finished background job")
		}
	}()
	return bgSpoc{spoc: c2, ch: ch}
}

// Wait until background job has finished, i.e. channel is closed,
// then forward messages of background job to main job.
func (c *spoc) collectMessages(c2 bgSpoc) {
	ch := c2.ch
	if ch == nil {
		return
	}
	<-ch
	if conf.Conf.TimeStamps {
		c.progress("Output of background job:")
	}
	if conf.Conf.TimeStamps {
		for i, msg := range c2.messages {
			if matched, _ := regexp.MatchString(`^\d+s `, msg); matched {
				c2.messages[i] = " " + msg
			}
		}
	}
	c.sendBuf(c2.spoc)
}

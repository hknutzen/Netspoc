package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
)

func (c *spoc) startInBackground(f func(*spoc)) <-chan spocMsg {
	if conf.Conf.ConcurrencyPass1 <= 1 {
		f(c)
		return nil
	}
	c2 := *c
	// If buffer is full, background job will wait until collector is
	// started. But typically we only expect a few messages.
	ch := make(chan spocMsg, 1000)
	c2.msgChan = ch
	go func() {
		f(&c2)
		if conf.Conf.TimeStamps {
			c2.progress("Finished background job")
		}
		close(ch)
	}()
	return ch
}

// Collect messages of background job and wait until background job
// has finished, i.e. channel is closed.
func (c *spoc) collectMessages(ch <-chan spocMsg) {
	if ch == nil {
		return
	}
	if conf.Conf.TimeStamps {
		c.progress("Output of background job:")
	}
	for m := range ch {
		if m.typ == progressM && conf.Conf.TimeStamps {
			m.text = " " + m.text
		}
		c.msgChan <- m
	}
}

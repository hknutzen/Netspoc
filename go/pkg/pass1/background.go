package pass1

import (
	"regexp"
)

type spocWait chan struct{}

// Start two functions concurrently if concurrency is enabled.
// Otherwise start first and second function sequentially.
func (c *spoc) startWithBackground(fg func(*spoc), bg func(*spoc)) {
	if c.conf.ConcurrencyPass1 <= 1 {
		fg(c)
		bg(c)
		return
	}
	// Start background job.
	// Channel is used to signal that background job has finished.
	ch := make(spocWait)
	c2 := c.bufferedSpoc()
	go handleBailout(
		func() {
			bg(c2)
			if c.conf.TimeStamps {
				c2.progress("Finished background job")
			}
		},
		func() { close(ch) })

	// Start foreground job
	fg(c)
	// Wait until background job has finished, i.e. channel is closed,
	// then forward messages of background job to main job.
	<-ch
	if c.conf.TimeStamps {
		c.progress("Output of background job:")
		re := regexp.MustCompile(`^\d+s `)
		for i, msg := range c2.messages {
			if matched := re.MatchString(msg); matched {
				c2.messages[i] = " " + msg
			}
		}
	}
	c.sendBuf(c2)
}

package pass2

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"os"
	"time"
)

func progress(msg string) {
	if conf.Conf.Verbose {
		if conf.Conf.TimeStamps {
			msg = fmt.Sprintf("%.0fs %s", time.Since(conf.StartTime).Seconds(), msg)
		}
		fmt.Fprintln(os.Stderr, msg)
	}
}

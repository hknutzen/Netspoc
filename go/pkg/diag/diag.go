package diag

import (
	"fmt"
	"github.com/hknutzen/go-Netspoc/pkg/conf"
	"os"
	"time"
)

func Info(format string, args ...interface{}) {
	if conf.Conf.Verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

func Msg(msg string) {
	if os.Getenv("SHOW_DIAG") != "" {
		fmt.Fprintln(os.Stderr, "DIAG: "+msg)
	}
}

func Progress(msg string) {
	if conf.Conf.Verbose {
		if conf.Conf.TimeStamps {
			msg = fmt.Sprintf("%.0fs %s", time.Since(conf.StartTime).Seconds(), msg)
		}
		Info(msg)
	}
}

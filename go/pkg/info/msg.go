package info

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"os"
)

func Msg(format string, args ...interface{}) {
	if !conf.Conf.Quiet {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

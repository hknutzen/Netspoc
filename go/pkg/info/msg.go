package info

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"os"
)

func Msg(format string, args ...interface{}) {
	if conf.Conf.Verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

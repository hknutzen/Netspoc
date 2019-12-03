package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"os"
	"strings"
)

func info(format string, args ...interface{}) {
	if conf.Conf.Verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

func debug(format string, args ...interface{}) {
	info(format, args...)
}

func checkAbort() {
	ErrorCounter++
	if ErrorCounter >= conf.Conf.MaxErrors {
		fmt.Fprintf(os.Stderr, "Aborted after %d errors\n", ErrorCounter)
		os.Exit(ErrorCounter)
	}
}

func abortOnError() {
	if ErrorCounter > 0 {
		fmt.Fprintf(os.Stderr, "Aborted with %d errors\n", ErrorCounter)
		os.Exit(ErrorCounter)
	}
}

func errMsg(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	checkAbort()
}

func internalErr(format string, args ...interface{}) {
	abortOnError()
	string := "Internal error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	checkAbort()
}

func warnMsg(format string, args ...interface{}) {
	string := "Warning: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
}

func warnOrErrMsg(errType conf.TriState, format string, args ...interface{}) {
	if errType == "warn" {
		warnMsg(format, args...)
	} else {
		errMsg(format, args...)
	}
}

func (l intfList) nameList() string {
	var names stringList
	for _, intf := range l {
		names.push(intf.name)
	}
	return " - " + strings.Join(names, "\n - ")
}

func (l netList) nameList() string {
	var names stringList
	for _, intf := range l {
		names.push(intf.name)
	}
	return " - " + strings.Join(names, "\n - ")
}

func (l stringerList) nameList() string {
	var names stringList
	for _, x := range l {
		names.push(x.String())
	}
	return " - " + strings.Join(names, "\n - ")
}

func (l stringList) nameList() string {
	return " - " + strings.Join(l, "\n - ")
}

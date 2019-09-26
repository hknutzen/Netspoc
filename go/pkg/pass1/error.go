package pass1

import (
	"fmt"
	"os"
	"time"
)

func info(format string, args ...interface{}) {
	if config.Verbose {
		string := fmt.Sprintf(format, args...)
		fmt.Fprintln(os.Stderr, string)
	}
}

func debug(format string, args ...interface{}) {
	info(format, args...)
}

func checkAbort() {
	ErrorCounter++
	if ErrorCounter >= config.MaxErrors {
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

func warnOrErrMsg(errType, format string, args ...interface{}) {
	if errType == "warn" {
		warnMsg(format, args...)
	} else {
		errMsg(format, args...)
	}
}

func progress(msg string) {
	if config.Verbose {
		if config.TimeStamps {
			msg = fmt.Sprintf("%3.0fs %s", time.Since(startTime).Seconds(), msg)
		}
		info(msg)
	}
}

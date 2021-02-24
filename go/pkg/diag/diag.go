package diag

import (
	"fmt"
	"os"
)

func Err(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

func Warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

func Msg(msg string) {
	if os.Getenv("SHOW_DIAG") != "" {
		fmt.Fprintln(os.Stderr, "DIAG: "+msg)
	}
}

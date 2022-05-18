package capture

import (
	"fmt"
	"io"
)

func CatchPanic(stderr io.Writer, f func() int) (status int) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Fprintf(stderr, "panic: %v\n", e)
			status = 1
		}
	}()
	return f()
}

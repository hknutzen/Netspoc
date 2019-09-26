package abort

import (
	"fmt"
	"os"
)

func Msg(format string, args ...interface{}) {
	string := "Error: " + fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, string)
	fmt.Fprintln(os.Stderr, "Aborted")
	os.Exit(1)
}

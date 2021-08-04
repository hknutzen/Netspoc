package pass1

import (
	"fmt"
	"os"
	"strings"
)

func debug(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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

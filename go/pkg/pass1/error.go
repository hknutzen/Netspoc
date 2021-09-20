package pass1

import (
	"fmt"
	"os"
	"strings"
)

func debug(f string, l ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", l...) }

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

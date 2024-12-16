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
	return names.nameList()
}

func (l netList) nameList() string {
	var names stringList
	for _, n := range l {
		name := n.name
		if n.isCombined46() {
			name = cond(n.ipV6, "IPv6", "IPv4") + " " + name
		}
		names.push(name)
	}
	return names.nameList()
}

func (l stringerList) nameList() string {
	var names stringList
	for _, x := range l {
		names.push(x.String())
	}
	return names.nameList()
}

func (l stringList) nameList() string {
	return " - " + strings.Join(l, "\n - ")
}

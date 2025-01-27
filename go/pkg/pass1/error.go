package pass1

import (
	"strings"
)

/*
func debug(f string, l ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", l...) }
*/

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
		names.push(n.vxName())
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

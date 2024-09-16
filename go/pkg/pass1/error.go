package pass1

import (
	"strings"
)

/*
func debug(f string, l ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", l...) }
*/

func (l stringerList[E]) nameList() string {
	var names stringList
	for _, x := range l {
		names.push((*x).String())
	}
	return names.nameList()
}

func (l stringList) nameList() string {
	return " - " + strings.Join(l, "\n - ")
}

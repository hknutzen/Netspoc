package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
)

func main() {
	rawMap := pass1.ImportFromPerl()
	pass1.CutNetspoc(rawMap)
}

package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/rename"
	"testing"
)

func TestRenameNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/rename-netspoc", chgInputT,
		rename.Main, chgInputCheck)
}

package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/removefrom"
	"testing"
)

func TestRemoveFromNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/remove-from-netspoc", chgInputT,
		removefrom.Main, chgInputCheck)
}

package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"testing"
)

func TestPrintGroup(t *testing.T) {
	runTestFiles(t, "../testdata/print-group", stdoutT,
		pass1.PrintGroupMain, stdoutCheck)
}

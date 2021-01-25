package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"testing"
)

func TestPrintService(t *testing.T) {
	runTestFiles(t, "../testdata/print-service", stdoutT,
		pass1.PrintServiceMain, stdoutCheck)
}

package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"gotest.tools/assert"
	"strings"
	"testing"
)

func TestCutNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/cut-netspoc", stdoutT,
		pass1.CutNetspocMain, stdoutCheck)
}

func stdoutCheck(t *testing.T, expected, stdout string) {
	// Remove empty lines.
	stdout = strings.ReplaceAll(stdout, "\n\n", "\n")
	assert.Equal(t, expected, stdout)
}

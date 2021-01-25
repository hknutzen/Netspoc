package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/format"
	"gotest.tools/assert"
	"testing"
)

func TestFormatNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/format-netspoc", chgInputT,
		format.Main, formatCheck)
}

func formatCheck(t *testing.T, expected, got string) {
	assert.Equal(t, expected, got)
}

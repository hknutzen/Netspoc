package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/addto"
	"gotest.tools/assert"
	"strings"
	"testing"
)

func TestAddToNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/add-to-netspoc", chgInputT,
		addto.Main, chgInputCheck)
}

func chgInputCheck(t *testing.T, expected, got string) {
	// Remove empty lines.
	got = strings.ReplaceAll(got, "\n\n", "\n")
	assert.Equal(t, expected, got)
}

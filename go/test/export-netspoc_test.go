package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"gotest.tools/assert"
	"io/ioutil"
	"path"
	"regexp"
	"strings"
	"testing"
)

func TestExportNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/export-netspoc", outDirT,
		pass1.ExportMain, exportCheck)
}

func exportCheck(t *testing.T, spec, dir string) {
	// Blocks of expected output are split by single lines of dashes,
	// followed by file name.
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(spec, -1)

	if il == nil || il[0][0] != 0 {
		t.Fatal("Output spec must start with dashed line")
	}
	for i, p := range il {
		marker := spec[p[0] : p[1]-1] // without trailing "\n"
		pName := strings.Trim(marker, "- ")
		if pName == "" {
			t.Fatal("Missing file name in dashed line of output spec")
		}
		start := p[1]
		end := len(spec)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		block := spec[start:end]

		t.Run(pName, func(t *testing.T) {
			data, err := ioutil.ReadFile(path.Join(dir, pName))
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, block, string(data))
		})
	}

}

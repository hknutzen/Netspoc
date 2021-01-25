package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/test/capture"
	"github.com/hknutzen/Netspoc/go/test/tstdata"
	"gotest.tools/assert"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCutNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/cut-netspoc", cutTest)
}

func cutTest(t *testing.T, d *tstdata.Descr) {

	// Prepare input directory.
	inDir, err := ioutil.TempDir("", "spoc_input")
	if err != nil {
		log.Fatal(err)
	}
	tstdata.PrepareInDir(inDir, d.Input)
	defer os.RemoveAll(inDir)
	os.Args = append(os.Args, inDir)

	// Add services as param.
	if d.Param != "" {
		os.Args = append(os.Args, strings.Split(d.Param, " ")...)
	}

	// Call cut-netspoc and read STDOUT.
	var status int
	var stdout string
	stderr := capture.Capture(&os.Stderr, func() {
		stdout = capture.Capture(&os.Stdout, func() {
			status = pass1.CutNetspocMain()
		})
	})

	// Check result.
	stderr = strings.ReplaceAll(stderr, inDir+"/", "")
	if status == 0 {
		if e := d.Error; e != "" {
			t.Error("Unexpected success")
			return
		}
		if d.Warning != "" || stderr != "" {
			if d.Warning == "NONE" {
				d.Warning = ""
			}
			assert.Equal(t, d.Warning, stderr)
		} else if d.Output == "" {
			t.Error("Missing output specification")
			return
		}
		if d.Output != "" {
			// Remove empty lines.
			stdout = strings.ReplaceAll(stdout, "\n\n", "\n")
			assert.Equal(t, d.Output, stdout)
		}
	} else {
		re := regexp.MustCompile(`(?ms)\nUsage: .*`)
		stderr = re.ReplaceAllString(stderr, "\n")
		assert.Equal(t, d.Error, stderr)
	}
}

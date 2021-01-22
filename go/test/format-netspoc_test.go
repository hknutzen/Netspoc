package netspoc_test

import (
	"github.com/hknutzen/Netspoc/go/pkg/format"
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

func TestFormatNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/format-netspoc", formatTest)
}

func formatTest(t *testing.T, d *tstdata.Descr) {
	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Prepare options.
	os.Args = []string{"print-group", "-q"}
	if d.Option != "" {
		options := strings.Split(d.Option, " ")
		os.Args = append(os.Args, options...)
	}

	// Prepare input file.
	f, err := ioutil.TempFile("", "spoc_input")
	if err != nil {
		log.Fatal(err)
	}
	inFile := f.Name()
	defer os.Remove(inFile)
	if d.Input == "NONE\n" {
		d.Input = ""
	}
	if err := ioutil.WriteFile(inFile, []byte(d.Input), 0644); err != nil {
		log.Fatal(err)
	}
	os.Args = append(os.Args, inFile)

	// Call format-netspoc
	var status int
	stderr := capture.Capture(&os.Stderr, func() {
		status = format.Main()
	})

	// Read formatted file.
	data, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Fatal(err)
	}
	out := string(data)

	// Check result.
	stderr = strings.ReplaceAll(stderr, inFile, "INPUT")
	if status == 0 {
		if e := d.Error; e != "" {
			t.Error("Unexpected success")
			return
		}
		if d.Warning != "" || stderr != "" {
			if d.Warning == "NONE\n" {
				d.Warning = ""
			}
			assert.Equal(t, d.Warning, stderr)
		} else if d.Output == "" {
			t.Error("Missing output specification")
			return
		}
		if d.Output != "" {
			assert.Equal(t, d.Output, out)
		}
	} else {
		re := regexp.MustCompile(`(?ms)\nUsage: .*`)
		stderr = re.ReplaceAllString(stderr, "\n")
		assert.Equal(t, d.Error, stderr)
	}
}

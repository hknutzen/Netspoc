package netspoc_test

import (
	"encoding/json"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/test/capture"
	"github.com/hknutzen/Netspoc/go/test/tstdata"
	"gotest.tools/assert"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

func TestExportNetspoc(t *testing.T) {
	runTestFiles(t, "../testdata/export-netspoc", exportTest)
}

func exportTest(t *testing.T, d *tstdata.Descr) {
	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Prepare options.
	os.Args = []string{"export-netspoc", "-q"}
	if d.Option != "" {
		options := strings.Split(d.Option, " ")
		os.Args = append(os.Args, options...)
	}

	// Prepare input directory.
	inDir, err := ioutil.TempDir("", "spoc_input")
	if err != nil {
		log.Fatal(err)
	}
	tstdata.PrepareInDir(inDir, d.Input)
	defer os.RemoveAll(inDir)
	os.Args = append(os.Args, inDir)

	// Prepare output directory
	var outDir string
	if d.Output != "" {
		outDir, err = ioutil.TempDir("", "spoc_output")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(outDir)
		os.Args = append(os.Args, outDir)
	}

	// Call export-netspoc
	var status int
	stderr := capture.Capture(&os.Stderr, func() {
		status = pass1.ExportMain()
	})

	// Check result.
	stderr = strings.ReplaceAll(stderr, inDir+"/", "")
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
			checkExported(t, d.Output, outDir)
		}
	} else {
		assert.Equal(t, d.Error, stderr)
	}
}

func checkExported(t *testing.T, spec, dir string) {
	// Blocks of expected output are split by single lines of dashes,
	// followed by file name.
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(spec, -1)

	if il == nil || il[0][0] != 0 {
		t.Error("Output spec must start with dashed line")
	}
	for i, p := range il {
		marker := spec[p[0] : p[1]-1] // without trailing "\n"
		pName := strings.Trim(marker, "- ")
		if pName == "" {
			t.Error("Missing file name in dashed line of output spec")
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
				t.Error(err)
			}
			// Compare JSON, if expected data looks like JSON.
			if ok, _ := regexp.MatchString(`^\s*[\{\[]`, block); ok {
				expJSON := new(interface{})
				gotJSON := new(interface{})
				if err = json.Unmarshal([]byte(block), expJSON); err != nil {
					t.Errorf("Invalid JSON in ouput: %v", err)
				}
				if err = json.Unmarshal(data, gotJSON); err != nil {
					t.Errorf("Invalid JSON spec: %s", err)
				}
				assert.DeepEqual(t, expJSON, gotJSON)
			} else {
				assert.Equal(t, block, string(data))
			}
		})
	}

}

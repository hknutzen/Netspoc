package netspoc_test

import (
	"bytes"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/pkg/testdata"
	"gotest.tools/assert"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

func TestPrintGroup(t *testing.T) {
	dataFiles := getTestDataFiles("../testdata/print-group")
	os.Unsetenv("SHOW_DIAG")
	for _, file := range dataFiles {
		file := file // capture range variable
		t.Run(path.Base(file), func(t *testing.T) {
			l, err := testdata.ParseFile(file)
			if err != nil {
				log.Fatal(err)
			}
			for _, descr := range l {
				descr := descr // capture range variable
				t.Run(descr.Title, func(t *testing.T) {
					groupTest(t, descr)
				})
			}
		})
	}
}

func groupTest(t *testing.T, d *testdata.Descr) {
	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Prepare options.
	os.Args = []string{"print-group", "-q"}
	if d.Option != "" {
		options := strings.Split(d.Option, " ")
		os.Args = append(os.Args, options...)
	}

	// Prepare input directory.
	inDir, err := ioutil.TempDir("", "spoc_input")
	if err != nil {
		log.Fatal(err)
	}
	prepareInDir(t, inDir, d.Input)
	defer os.RemoveAll(inDir)
	os.Args = append(os.Args, inDir)

	// Add group as param.
	if d.Param != "" {
		os.Args = append(os.Args, d.Param)
	}

	if d.ShowDiag {
		os.Setenv("SHOW_DIAG", "1")
		defer os.Unsetenv("SHOW_DIAG")
	}

	// Call print-group
	var status int
	var stdout string
	stderr := capture(&os.Stderr, func() {
		stdout = capture(&os.Stdout, func() { status = pass1.PrintGroupMain() })
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
			assert.Equal(t, d.Output, stdout)
		}
	} else {
		re := regexp.MustCompile(`\nAborted with \d+ error\(s\)`)
		stderr = re.ReplaceAllString(stderr, "")
		re = regexp.MustCompile(`(?ms)\nUsage: .*`)
		stderr = re.ReplaceAllString(stderr, "\n")
		assert.Equal(t, d.Error, stderr)
	}
}

func capture(std **os.File, f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	old := *std
	*std = w
	defer func() {
		*std = old
	}()

	out := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		out <- buf.String()
	}()

	f()

	w.Close()
	return <-out
}

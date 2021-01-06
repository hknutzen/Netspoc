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

const dataDir = "../testdata"

func TestNetspoc(t *testing.T) {
	dataFiles := getTestDataFiles()
	for _, file := range dataFiles {
		l, err := testdata.ParseFile(file)
		if err != nil {
			log.Fatal(err)
		}
		for _, descr := range l {
			log.Println(descr.Title)
			descr := descr // capture range variable
			t.Run(descr.Title, func(t *testing.T) {
				runTestDescription(t, descr)
			})
		}
	}
}

func getTestDataFiles() []string {
	files, err := ioutil.ReadDir(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	var names []string
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".t") {
			name = path.Join(dataDir, name)
			names = append(names, name)
		}
	}
	return names
}

func runTestDescription(t *testing.T, d *testdata.Descr) {
	file, err := ioutil.TempFile("", "netspoc")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write([]byte(d.Input)); err != nil {
		log.Fatal(err)
	}
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
	os.Args = []string{"spoc1", "-q"}
	if d.Option != "" {
		options := strings.Split(d.Option, " ")
		os.Args = append(os.Args, options...)
	}
	var status int
	stderr := captureStderr(func() { status = pass1.SpocMain() })
	if status == 0 {
		t.Error("Unexpected success")
	} else {
		re := regexp.MustCompile(`Aborted with \d+ error\(s\)\n`)
		stderr = re.ReplaceAllString(stderr, "")
		assert.Equal(t, d.Error, stderr)
	}
}

func captureStderr(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	stderr := os.Stderr
	os.Stderr = w
	defer func() {
		os.Stderr = stderr
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

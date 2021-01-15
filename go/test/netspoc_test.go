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
	inDir, err := ioutil.TempDir("", "spoc_input")
	if err != nil {
		log.Fatal(err)
	}
	prepareInDir(inDir, d.Input)
	defer os.RemoveAll(inDir)
	os.Args = []string{"spoc1", "-q"}
	if d.Option != "" {
		options := strings.Split(d.Option, " ")
		os.Args = append(os.Args, options...)
	}
	os.Args = append(os.Args, inDir)
	var status int
	stderr := captureStderr(func() { status = pass1.SpocMain() })
	stderr = strings.ReplaceAll(stderr, inDir+"/", "")
	if status == 0 {
		if e := d.Error; e != "" {
			t.Error("Unexpected success")
		} else if d.Warning != "" {
			assert.Equal(t, d.Warning, stderr)
		} else {
		}
	} else {
		re := regexp.MustCompile(`\nAborted with \d+ error\(s\)`)
		stderr = re.ReplaceAllString(stderr, "")
		re = regexp.MustCompile(`(?ms)\nUsage: .*`)
		stderr = re.ReplaceAllString(stderr, "\n")
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

// Fill input directory with file(s).
// 'input' is optionally preceeded by single lines of dashes
// followed by a filename.
// If no filenames are given, a single file named STDIN is used.
func prepareInDir(inDir, input string) {
	re := regexp.MustCompile(`(?ms)^-+[ ]*(\S+)[ ]*\n`)
	il := re.FindAllStringIndex(input, -1)

	write := func(pName, data string) {
		if path.IsAbs(pName) {
			log.Fatalf("Unexpected absolute path '%s'", pName)
		}
		dir, file := path.Split(pName)
		fullDir := path.Join(inDir, dir)
		if err := os.MkdirAll(fullDir, 0644); err != nil {
			log.Fatal(err)
		}
		fullPath := path.Join(fullDir, file)
		if err := ioutil.WriteFile(fullPath, []byte(data), 0644); err != nil {
			log.Fatal(err)
		}
	}

	// No filename
	if il == nil {
		write("STDIN", input)
	} else if il[0][0] != 0 {
		log.Fatal("Missing file marker in first line")
	} else {
		for i, p := range il {
			marker := input[p[0] : p[1]-1] // without trailing "\n"
			pName := strings.Trim(marker, "- ")
			start := p[1]
			end := len(input)
			if i+1 < len(il) {
				end = il[i+1][0]
			}
			data := input[start:end]
			write(pName, data)
		}
	}
}

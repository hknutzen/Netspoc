package netspoc_test

import (
	"bytes"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
	"github.com/hknutzen/Netspoc/go/pkg/testdata"
	"gotest.tools/assert"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestNetspoc(t *testing.T) {
	dataFiles := getTestDataFiles("../testdata")
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
					runTestDescription(t, descr)
				})
			}
		})
	}
}

func getTestDataFiles(dataDir string) []string {
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
	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Prepare options.
	os.Args = []string{"spoc1", "-q"}
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

	// Add extra params for testing command line handling.
	if d.Param != "" {
		os.Args = append(os.Args, strings.Split(d.Param, " ")...)
	}

	if d.ShowDiag {
		os.Setenv("SHOW_DIAG", "1")
		defer os.Unsetenv("SHOW_DIAG")
	}

	// Call pass1 + pass2.
	var status int
	stderr := captureStderr(func() { status = pass1.SpocMain() })
	if status == 0 {
		stderr += captureStderr(func() { pass2.Spoc2Main() })
	}

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
			checkOutput(t, d.Output, outDir)
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
// Parts of input are preceeded by single lines of dashes
// followed by a filename.
// If no filenames are given, a single file named STDIN is used.
func prepareInDir(t *testing.T, inDir, input string) {
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(input, -1)

	write := func(pName, data string) {
		if path.IsAbs(pName) {
			log.Fatalf("Unexpected absolute path '%s'", pName)
		}
		dir, file := path.Split(pName)
		fullDir := path.Join(inDir, dir)
		if err := os.MkdirAll(fullDir, 0755); err != nil {
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

func checkOutput(t *testing.T, spec, dir string) {
	// Blocks of expected output are split by single lines of dashes,
	// followed by an optional device name.
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S*[ ]*\n`)
	il := re.FindAllStringIndex(spec, -1)

	if il == nil || il[0][0] != 0 {
		t.Error("Output spec must start with dashed line")
	}
	var device string
	var devices []string
	device2blocks := make(map[string][]string)
	for i, p := range il {
		marker := spec[p[0] : p[1]-1] // without trailing "\n"
		pName := strings.Trim(marker, "- ")
		if device == "" && pName == "" {
			t.Error("Missing device name in first dashed line of output spec")
		}
		if pName != "" {
			device = pName
		}
		start := p[1]
		end := len(spec)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		block := spec[start:end]
		if _, found := device2blocks[device]; !found {
			devices = append(devices, device)
		}
		device2blocks[device] = append(device2blocks[device], block)
	}
	sort.Strings(devices)
	for _, device := range devices {
		data, err := ioutil.ReadFile(path.Join(dir, device))
		if err != nil {
			t.Error(err)
		}
		blocks := device2blocks[device]
		expected := strings.Join(blocks, "")
		assert.Equal(t, expected, getBlocks(string(data), blocks))
	}
}

// Find lines in data which equal one of first lines in blocks.
// Output found lines and subsequent lines up to empty line or comment line.
func getBlocks(data string, blocks []string) string {
	find := make(map[string]bool)
	for _, block := range blocks {
		end := len(block)
		if idx := strings.Index(block, "\n"); idx != -1 {
			end = idx
		}
		line := block[0:end]
		find[line] = true
	}
	out := ""
	match := false
	for _, line := range strings.Split(data, "\n") {
		if find[line] {
			out += line + "\n"
			match = true
		} else if match {
			check := strings.TrimSpace(line)
			if check == "" || check[0] == '#' || check[0] == '!' {
				match = false
			} else {
				out += line + "\n"
			}
		}
	}
	return out
}

package netspoc_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/addto"
	"github.com/hknutzen/Netspoc/go/pkg/api"
	"github.com/hknutzen/Netspoc/go/pkg/expand"
	"github.com/hknutzen/Netspoc/go/pkg/format"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
	"github.com/hknutzen/Netspoc/go/pkg/removefrom"
	"github.com/hknutzen/Netspoc/go/pkg/rename"
	"github.com/hknutzen/Netspoc/go/test/capture"
	"github.com/hknutzen/Netspoc/go/test/tstdata"
	"gotest.tools/assert"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	outDirT = iota
	stdoutT
	chgInputT
	outDirStdoutT // hybrid case
)

type test struct {
	dir   string
	typ   int
	run   func() int
	check func(*testing.T, string, string)
}

var tests = []test{
	{".", outDirT, pass1.SpocMain, netspocCheck},
	{"ipv6", outDirT, pass1.SpocMain, netspocCheck},
	{"export-netspoc", outDirT, pass1.ExportMain, exportCheck},
	{"format-netspoc", chgInputT, format.Main, formatCheck},
	{"add-to-netspoc", chgInputT, addto.Main, chgInputCheck},
	{"expand-group", chgInputT, expand.Main, chgInputCheck},
	{"remove-from-netspoc", chgInputT, removefrom.Main, chgInputCheck},
	{"rename-netspoc", chgInputT, rename.Main, chgInputCheck},
	{"api", stdoutT, modifyRun, stdoutCheck},
	{"cut-netspoc", stdoutT, pass1.CutNetspocMain, stdoutCheck},
	{"print-group", stdoutT, pass1.PrintGroupMain, stdoutCheck},
	{"print-service", stdoutT, pass1.PrintServiceMain, stdoutCheck},
	{"check-acl", outDirStdoutT, checkACLRun, stdoutCheck},
}

var count int

func TestNetspoc(t *testing.T) {
	os.Unsetenv("LANG")
	count = 0
	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.dir, func(t *testing.T) {
			runTestFiles(t, tc)
		})
	}
	t.Logf("Checked %d assertions", count)
}

func runTestFiles(t *testing.T, tc test) {
	dataFiles := tstdata.GetFiles("../testdata/" + tc.dir)
	os.Unsetenv("SHOW_DIAG")
	for _, file := range dataFiles {
		file := file // capture range variable
		t.Run(path.Base(file), func(t *testing.T) {
			l, err := tstdata.ParseFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, descr := range l {
				descr := descr // capture range variable
				t.Run(descr.Title, func(t *testing.T) {
					runTest(t, tc, descr)
				})
			}
		})
	}
}

func runTest(t *testing.T, tc test, d *tstdata.Descr) {

	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Run each test inside a fresh working directory,
	// where different subdirectories are created.
	workDir := t.TempDir()
	prevDir, _ := os.Getwd()
	defer func() { os.Chdir(prevDir) }()
	os.Chdir(workDir)

	// Prepare output directory.
	var outDir string
	if tc.typ == outDirT && d.Output != "" || tc.typ == outDirStdoutT ||
		d.WithOutD {

		outDir = path.Join(workDir, "out")
	}

	// Execute optional shell commands to setup error cases
	// in working directory.
	if d.Setup != "" {
		for _, line := range strings.Split(d.Setup, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				continue
			}
			words := strings.Fields(line)
			prog := words[0]
			args := words[1:]
			cmd := exec.Command(prog, args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(fmt.Sprintf("executing '%v': %v\n%s", cmd, err, out))
			}
		}
	}

	runProg := func(input string) (int, string, string, string) {

		// Initialize os.Args, add default options.
		os.Args = []string{"PROGRAM", "-q"}

		// Add more options.
		if d.Options != "" {
			options := strings.Fields(d.Options)
			os.Args = append(os.Args, options...)
		}

		// Prepare file for option '-f file'
		if d.FOption != "" {
			name := path.Join(workDir, "file")
			if err := os.WriteFile(name, []byte(d.FOption), 0644); err != nil {
				t.Fatal(err)
			}
			os.Args = append(os.Args, "-f", name)
		}

		var inDir string
		if input != "NONE" || outDir != "" {
			// Prepare input directory.
			inDir = path.Join(workDir, "netspoc")
			tstdata.PrepareInDir(inDir, input)
			os.Args = append(os.Args, inDir)

			// Add location of output directory.
			if outDir != "" {
				os.Args = append(os.Args, outDir)
			}
		}

		// Prepare job file as param.
		if d.Job != "" {
			name := path.Join(workDir, "job")
			if err := os.WriteFile(name, []byte(d.Job), 0644); err != nil {
				t.Fatal(err)
			}
			os.Args = append(os.Args, name)
		}

		// Add other params to command line.
		if d.Params != "" {
			os.Args = append(os.Args, strings.Fields(d.Params)...)
		}
		if d.Param != "" {
			os.Args = append(os.Args, d.Param)
		}

		if d.ShowDiag {
			os.Setenv("SHOW_DIAG", "1")
		} else {
			os.Unsetenv("SHOW_DIAG")
		}

		// Call main function.
		var status int
		var stdout string
		stderr := capture.Capture(&os.Stderr, func() {
			stdout = capture.Capture(&os.Stdout, func() {
				status = tc.run()
			})
		})

		return status, stdout, stderr, inDir
	}

	// Run program once.
	status, stdout, stderr, inDir := runProg(d.Input)

	// Run again, to check if output is reused.
	if d.ReusePrev != "" {
		if status != 0 {
			t.Error("Unexpected failure with =REUSE_PREV=")
			return
		}
		status, stdout, stderr, inDir = runProg(d.ReusePrev)
	}

	// Normalize stderr.
	if inDir != "" {
		stderr = strings.ReplaceAll(stderr, inDir+"/", "")
	}
	if outDir != "" {
		stderr = strings.ReplaceAll(stderr, outDir+"/", "")
		stderr = strings.ReplaceAll(stderr, outDir, "")
	}
	if d.Job != "" {
		stderr = strings.ReplaceAll(stderr, workDir+"/", "")
	}
	re := regexp.MustCompile(`Netspoc, version .*`)
	stderr = re.ReplaceAllString(stderr, "Netspoc, version TESTING")
	re = regexp.MustCompile(`[ \t]+\n`)
	stderr = re.ReplaceAllString(stderr, "\n")

	// Check result.
	if status == 0 {
		if d.Error != "" {
			t.Error("Unexpected success")
			return
		}
		if d.Warning != "" || stderr != "" {
			if d.Warning == "NONE" {
				d.Warning = ""
			}
			t.Run("Warning", func(t *testing.T) {
				countEq(t, d.Warning, stderr)
			})
		} else if d.Output == "" {
			t.Error("Missing output specification")
			return
		}
	} else {
		if d.Error == "" {
			t.Error("Unexpected failure")
		}
		re := regexp.MustCompile(`\nAborted with \d+ error\(s\)`)
		stderr = re.ReplaceAllString(stderr, "")
		re = regexp.MustCompile(`\nUsage: .*(?:\n\s.*)*`)
		stderr = re.ReplaceAllString(stderr, "")
		countEq(t, d.Error, stderr)
	}
	if d.Output != "" {
		if d.Output == "NONE" {
			d.Output = ""
		}
		var got string
		switch tc.typ {
		case outDirT:
			got = outDir
		case stdoutT, outDirStdoutT:
			got = stdout
		case chgInputT:
			got = inDir
		}
		tc.check(t, d.Output, got)
	}
}

func netspocCheck(t *testing.T, spec, dir string) {
	// Blocks of expected output are split by single lines of dashes,
	// followed by an optional device name.
	re := regexp.MustCompile(`(?ms)^-+[ ]*(?:\w\S*)?[ ]*\n`)
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
		data, err := os.ReadFile(path.Join(dir, device))
		if err != nil {
			t.Error(err)
		}
		blocks := device2blocks[device]
		expected := strings.Join(blocks, "")
		t.Run(device, func(t *testing.T) {
			countEq(t, expected, getBlocks(string(data), blocks))
		})
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
			data, err := os.ReadFile(path.Join(dir, pName))
			if err != nil {
				t.Fatal(err)
			}
			jsonEq(t, block, data)
		})
	}
}

func chgInputCheck(t *testing.T, spec, dir string) {
	got := readChangedFiles(t, dir)
	// Remove empty lines.
	got = strings.ReplaceAll(got, "\n\n", "\n")
	countEq(t, spec, got)
}

func formatCheck(t *testing.T, expected, dir string) {
	got := readChangedFiles(t, dir)
	countEq(t, expected, got)
}

func readChangedFiles(t *testing.T, dir string) string {
	var got string
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(path.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !(len(files) == 1 && file.Name() == "INPUT") {
			got += "-- " + file.Name() + "\n"
		}
		got += string(data)
	}
	return got
}

func stdoutCheck(t *testing.T, expected, stdout string) {
	// Remove empty lines.
	stdout = strings.ReplaceAll(stdout, "\n\n", "\n")
	countEq(t, expected, stdout)
}

func countEq(t *testing.T, expected, got string) {
	count++
	assert.Equal(t, expected, got)
}

func jsonEq(t *testing.T, expected string, got []byte) {
	normalize := func(d []byte) string {
		var v interface{}
		if err := json.Unmarshal(d, &v); err != nil {
			// Try to compare as non JSON value
			return string(d)
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		enc.Encode(v)
		return b.String()
	}
	countEq(t, normalize([]byte(expected)), normalize(got))
}

// Run modify-netspoc-api and netspoc sequentially.
// Show diff on stdout.
// Arguments: PROGRAM -q netspoc job
func modifyRun() int {
	// Make copy for diff.
	err := exec.Command("cp", "-r", "netspoc", "unchanged").Run()

	status := api.Main()
	if err == nil {
		cmd := exec.Command("sh", "-c",
			"diff -u -r -N unchanged netspoc"+
				"| sed "+
				" -e 's/^ $//'"+
				" -e '/^@@ .*/d'"+
				" -e 's|^diff -u -r -N unchanged/[^ ]\\+ netspoc/|@@ |'"+
				" -e '/^--- /d'"+
				" -e '/^+++ /d'")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
	if status == 0 {
		os.Args = os.Args[:3]
		status = pass1.SpocMain()
	}
	return status
}

// Run Netspoc pass1 + check-acl sequentially.
// Arguments: PROGRAM -q [-6] [-f file] input code router acl <packet>
func checkACLRun() int {
	args := os.Args
	// Args: PROGRAM -q [-6] input code
	var p1Args []string
	// Args: PROGRAM [-f file] code/router acl <packet>
	var chArgs []string
	p1Args = append(p1Args, args[0:2]...) // PROGRAM -q
	chArgs = append(chArgs, args[0])      // PROGRAM
	a := 0
	if args[2] == "-6" {
		p1Args = append(p1Args, args[2])
		a = 1
	}
	if args[2+a] == "-f" {
		chArgs = append(chArgs, args[2+a:4+a]...) // -f file
		a += 2
	}
	p1Args = append(p1Args, args[2+a:4+a]...)                // input code
	chArgs = append(chArgs, path.Join(args[3+a], args[4+a])) // code/router
	chArgs = append(chArgs, args[5+a:]...)
	os.Args = p1Args
	status := pass1.SpocMain()
	if status != 0 {
		return status
	}
	os.Args = chArgs
	return pass2.CheckACLMain()
}

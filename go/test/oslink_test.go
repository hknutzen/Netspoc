package netspoc_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"github.com/hknutzen/Netspoc/go/test/capture"
	"github.com/hknutzen/Netspoc/go/test/tstdata"
)

func TestOsLink(t *testing.T) {
	type testData struct {
		title  string
		param  string
		run    func(oslink.Data) int
		input  string
		stdout string
		stderr string
		diag   bool
	}
	tests := []testData{
		{
			title: "Test stderr",
			run:   pass1.SpocMain,
			input: "INVALID",
			stderr: `Error: Typed name expected at line 1 of netspoc/INPUT, near "--HERE-->INVALID"
Aborted
`,
		},
		{
			title: "Test SHOW_DIAG",
			run:   pass1.SpocMain,
			input: `
network:n1 = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.10; }
 host:h2 = { ip = 10.1.2.11; }
}
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
`,
			stderr: `Warning: Duplicate rules in service:test1b and service:test1a:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
`,
			diag: true,
		},
		{
			title: "Test stdout",
			param: "network:n1",
			run:   pass1.PrintGroupMain,
			input: "network:n1 = { ip = 10.1.1.0/24; }",
			stdout: "10.1.1.0/24	network:n1\n",
		},
	}
	for _, descr := range tests {
		descr := descr // capture range variable
		t.Run(descr.title, func(t *testing.T) {
			workDir := t.TempDir()
			os.Chdir(workDir)
			os.Args = []string{"PROGRAM", "-q"}
			inDir := "netspoc"
			tstdata.PrepareInDir(inDir, descr.input)
			os.Args = append(os.Args, inDir)
			if p := descr.param; p != "" {
				os.Args = append(os.Args, p)
			}
			if descr.diag {
				os.Setenv("SHOW_DIAG", "1")
			} else {
				os.Unsetenv("SHOW_DIAG")
			}
			var stdout string
			stderr := capture.Capture(&os.Stderr, func() {
				stdout = capture.Capture(&os.Stdout, func() {
					descr.run(oslink.Get())
				})
			})
			if d := cmp.Diff(descr.stdout, stdout); d != "" {
				t.Error(d)
			}
			if d := cmp.Diff(descr.stderr, stderr); d != "" {
				t.Error(d)
			}
		})
	}
}

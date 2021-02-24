package conf

/*
Get arguments and options from command line and config file.

=head1 COPYRIGHT AND DISCLAIMER

(C) 2021 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/octago/sflags"
	"github.com/octago/sflags/gen/gpflag"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Type for command line flag with value 0|1|warn
type TriState string

func (v *TriState) String() string { return string(*v) }
func (v *TriState) Set(s string) error {
	switch strings.ToLower(s) {
	case "", "0", "no", "f", "false":
		*v = ""
	case "1", "e", "err", "error":
		*v = "err"
	case "w", "warn", "warning":
		*v = "warn"
	default:
		return fmt.Errorf("Expected 0|1|warn but got %s", s)
	}
	return nil
}

// Needed for gen/gpflag to work, mostly for pflag compatibility.
func (v TriState) Type() string { return "tristate" }

// Type for additional name to existing flag with inverted boolean value.
type invFlag struct{ flag *flag.Flag }

func (v invFlag) String() string {
	b, _ := strconv.ParseBool(v.flag.Value.String())
	return strconv.FormatBool(!b)
}
func (v invFlag) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	inverted := strconv.FormatBool(!b)
	v.flag.Value.Set(inverted)
	return nil
}
func (v invFlag) Type() string { return "invFlag" }

// Config holds program flags.
type Config struct {
	CheckDuplicateRules          TriState
	CheckFullyRedundantRules     TriState
	CheckIdenticalServices       TriState
	CheckPolicyDistributionPoint TriState
	CheckRedundantRules          TriState
	CheckServiceMultiOwner       TriState
	CheckServiceUnknownOwner     TriState
	CheckSubnets                 TriState
	CheckSupernetRules           TriState
	CheckTransientSupernetRules  TriState
	CheckUnenforceable           TriState
	CheckUnusedGroups            TriState
	CheckUnusedOwners            TriState
	CheckUnusedProtocols         TriState
	AutoDefaultRoute             bool
	ConcurrencyPass1             int
	ConcurrencyPass2             int
	IgnoreFiles                  *regexp.Regexp
	IPV6                         bool `flag:"ipv6 6"`
	MaxErrors                    int  `flag:"max_errors m"`
	Verbose                      bool `flag:"verbose v"`
	TimeStamps                   bool `flag:"time_stamps t"`
	StartTime                    int64
	Pipe                         bool
}

type invertedFlag map[string]*struct {
	short string
	orig  string
}

var invertedFlags = invertedFlag{
	"quiet": {short: "q", orig: "verbose"},
}

func defaultOptions(fs *flag.FlagSet) *Config {
	cfg := &Config{

		// Check for unused groups and protocolgroups.
		CheckUnusedGroups: "warn",

		// Check for unused owners.
		CheckUnusedOwners: "warn",

		// Check for unused protocol definitions.
		CheckUnusedProtocols: "",

		// Allow subnets only
		// if the enclosing network is marked as 'has_subnets' or
		// if the subnet is marked as 'subnet_of'
		CheckSubnets: "warn",
		// Check for unenforceable rules, i.e. no managed device between
		// src and dst.
		CheckUnenforceable: "warn",

		// Check for different services with identical rule definitions.
		CheckIdenticalServices: "",

		// Check for duplicate rules.
		CheckDuplicateRules: "warn",

		// Check for redundant rules.
		CheckRedundantRules:      "warn",
		CheckFullyRedundantRules: "",

		// Check for services where owner can't be derived.
		CheckServiceUnknownOwner: "",

		// Check for services where multiple owners have been derived.
		CheckServiceMultiOwner: "warn",

		// Check for missing supernet rules.
		CheckSupernetRules: "warn",

		// Check for transient supernet rules.
		CheckTransientSupernetRules: "warn",

		// Check, that all managed routers have attribute
		// 'policy_distribution_point', either directly or from inheritance.
		CheckPolicyDistributionPoint: "",

		// Optimize the number of routing entries per router:
		// For each router find the hop, where the largest
		// number of routing entries points to
		// and replace them with a single default route.
		// This is only applicable for internal networks
		// which have no default route to the internet.
		AutoDefaultRoute: true,

		// Ignore these names when reading directories:
		// - CVS and RCS directories
		// - CVS working files
		// - Editor backup files: emacs: *~
		IgnoreFiles: regexp.MustCompile("^(CVS|RCS|\\.#.*|.*~)$"),
		// Use IPv4 version as default
		IPV6: false,

		// Set value to >= 2 to start concurrent processing.
		ConcurrencyPass1: 1,
		ConcurrencyPass2: 1,

		// Abort after this many errors.
		MaxErrors: 10,

		// Print progress messages.
		Verbose: true,

		// Print progress messages with time stamps.
		// Print "finished" with time stamp when finished.
		TimeStamps: false,

		// Use this value when printing passed time span.
		StartTime: 0,

		// Pass 1 writes processed device names to STDOUT,
		// pass 2 reads to be processed device names from STDIN.
		Pipe: false,
	}
	err := gpflag.ParseTo(cfg, fs, sflags.FlagDivider("_"))
	if err != nil {
		panic(err)
	}
	for name, spec := range invertedFlags {
		origFlag := fs.Lookup(spec.orig)
		inverted := invFlag{origFlag}
		flag := fs.VarPF(inverted, name, spec.short, "")
		flag.NoOptDefVal = "true"
	}
	return cfg
}

func usage(format string, args ...interface{}) {
	diag.Err(format, args...)
	flag.Usage()
}

// Read names of input file/directory and output directory from
// passed command line arguments.
func parseArgs(fs *flag.FlagSet) (string, string, bool) {
	mainFile := fs.Arg(0)
	if mainFile == "" || fs.Arg(2) != "" {
		usage("Expected 2 args, got %v", fs.Args())
		return "", "", true
	}

	// outDir is used to store compilation results.
	// For each managed router with name X a corresponding file X
	// is created in outDir.
	// If outDir is missing, no code is generated.
	outDir := fs.Arg(1)

	// Strip trailing slash for nicer messages.
	strings.TrimSuffix(mainFile, "/")
	strings.TrimSuffix(outDir, "/")
	return mainFile, outDir, false
}

// Reads "key = value;" pairs from config file.
// Trailing ";" is optional.
// Comment lines starting with "#" are ignored.
func readConfig(filename string) (map[string]string, bool) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		diag.Err("%v", err)
		return nil, true
	}
	lines := strings.Split(string(bytes), "\n")
	result := make(map[string]string)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			diag.Err("Unexpected line in %s: %s", filename, line)
			return nil, true
		}
		key, val := parts[0], parts[1]
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.TrimSuffix(val, ";")
		result[key] = val
	}
	return result, false
}

// parseFile parses the specified configuration file and populates unset flags
// in fs based on the contents of the file.
// Hidden flags are not set from file.
func parseFile(filename string, fs *flag.FlagSet) bool {
	isSet := make(map[*flag.Flag]bool)
	config, abort := readConfig(filename)
	if abort {
		return abort
	}

	fs.Visit(func(f *flag.Flag) {
		isSet[f] = true
	})
	hasErr := false
	fs.VisitAll(func(f *flag.Flag) {
		// Ignore inverted flag.
		if inv, found := invertedFlags[f.Name]; found {
			if isSet[f] {
				// Ignore inverted value from file.
				delete(config, inv.orig)
			}
			return
		}
		val, found := config[f.Name]
		if !found {
			return
		}
		delete(config, f.Name)
		if isSet[f] {
			return
		}
		err := f.Value.Set(val)
		if err != nil {
			hasErr = true
			diag.Err("Invalid value for %s in %s: %s", f.Name, filename, val)
		}
	})

	for name := range config {
		diag.Err("Invalid keyword in %s: %s", filename, name)
		hasErr = true
	}
	return hasErr
}

func addConfigFromFile(inDir string, fs *flag.FlagSet) bool {
	path := inDir + "/config"
	if !fileop.IsRegular(path) {
		return false
	}
	return parseFile(path, fs)
}

func setStartTime() {
	if Conf.StartTime != 0 {
		StartTime = time.Unix(Conf.StartTime, 0)
	} else {
		StartTime = time.Now()
	}
}

var Conf *Config
var StartTime time.Time

func GetArgs() (string, string, bool) {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	// Setup custom usage function.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] IN-DIR|IN-FILE [CODE-DIR]\n", os.Args[0])
		fs.PrintDefaults()
	}

	Conf = defaultOptions(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return "", "", true
		}
		usage("%v", err)
		return "", "", true
	}
	inPath, outDir, abort := parseArgs(fs)
	if abort {
		return "", "", true
	}
	if abort := addConfigFromFile(inPath, fs); abort {
		return "", "", true
	}
	setStartTime()
	return inPath, outDir, false
}

func ConfigFromArgsAndFile(args []string, path string) {
	fs := flag.NewFlagSet("", flag.ExitOnError)
	Conf = defaultOptions(fs)
	fs.Parse(args) // No check for error needed, because arguments are fixed.
	addConfigFromFile(path, fs)
	setStartTime()
}

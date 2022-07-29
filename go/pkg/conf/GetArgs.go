package conf

/*
Get arguments and options from command line and config file.

=head1 COPYRIGHT AND DISCLAIMER

(C) 2022by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/octago/sflags"
	"github.com/octago/sflags/gen/gpflag"
	flag "github.com/spf13/pflag"
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
	IPV6                         bool `flag:"ipv6 6"`
	MaxErrors                    int  `flag:"max_errors m"`
	Quiet                        bool `flag:"quiet q"`
	TimeStamps                   bool `flag:"time_stamps t"`
	DebugPass2                   string
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

		// Use IPv4 version as default
		IPV6: false,

		// Set value to >= 2 to start concurrent processing.
		ConcurrencyPass1: 1,
		ConcurrencyPass2: 1,

		// Abort after this many errors.
		MaxErrors: 10,

		// Print progress messages.
		Quiet: false,

		// Print progress messages with time stamps.
		// Print "finished" with time stamp when finished.
		TimeStamps: false,

		// Debug pass2, argument is filename of device, e.g. NAME or ipv6/NAME.
		DebugPass2: "",
	}
	gpflag.ParseTo(cfg, fs, sflags.FlagDivider("_"))
	return cfg
}

// Reads "key = value;" pairs from config file.
// "key;" is read as "key = ;"
// Trailing ";" is optional.
// Comment lines starting with "#" are ignored.
func readConfig(filename string) (map[string]string, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Can't %v", err)
	}
	lines := strings.Split(string(bytes), "\n")
	result := make(map[string]string)
	for _, line := range lines {
		line := strings.TrimSpace(line)
		line = strings.TrimSuffix(line, ";")
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := parts[0]
		val := ""
		if len(parts) == 2 {
			val = parts[1]
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		result[key] = val
	}
	return result, nil
}

// parseFile parses the specified configuration file and populates unset flags
// in fs based on the contents of the file.
// Hidden flags are not set from file.
func parseFile(filename string, fs *flag.FlagSet) error {
	isSet := make(map[*flag.Flag]bool)
	config, err := readConfig(filename)
	if err != nil {
		return err
	}

	fs.Visit(func(f *flag.Flag) {
		isSet[f] = true
	})
	var errList []string
	addErr := func(format string, args ...interface{}) {
		errList = append(errList, fmt.Sprintf(format, args...))
	}
	fs.VisitAll(func(f *flag.Flag) {
		val, found := config[f.Name]
		if !found {
			return
		}
		delete(config, f.Name)
		if isSet[f] {
			return
		}
		if err := f.Value.Set(val); err != nil {
			addErr("bad value in '%s = %s'", f.Name, val)
		}
	})

	for name := range config {
		addErr("bad keyword '%s'", name)
	}
	if errList != nil {
		return fmt.Errorf("Invalid line in %s:\n - %s",
			filename, strings.Join(errList, "\n - "))
	}
	return nil
}

func addConfigFromFile(inDir string, fs *flag.FlagSet) error {
	path := inDir + "/config"
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return parseFile(path, fs)
}

func GetArgs(d oslink.Data) (string, string, *Config, bool) {
	fs := flag.NewFlagSet(d.Args[0], flag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] IN-DIR|IN-FILE [CODE-DIR]\n%s",
			d.Args[0], fs.FlagUsages())
	}

	cnf := defaultOptions(fs)
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return "", "", nil, true
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return "", "", nil, true
	}
	// Read names of input file/directory and output directory from
	// passed command line arguments.
	inPath := fs.Arg(0)
	if inPath == "" || fs.Arg(2) != "" {
		fmt.Fprintf(d.Stderr, "Error: Expected 1 or 2 args, but got %d\n",
			fs.NArg())
		fs.Usage()
		return "", "", nil, true
	}
	// outDir is used to store compilation results.
	// For each managed router with name X a corresponding file X
	// is created in outDir.
	// If outDir is missing, no code is generated.
	outDir := fs.Arg(1)

	if err := addConfigFromFile(inPath, fs); err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return "", "", nil, true
	}
	return inPath, outDir, cnf, false
}

func ConfigFromArgsAndFile(args []string, path string) *Config {
	fs := flag.NewFlagSet("", flag.ExitOnError)
	cnf := defaultOptions(fs)
	// No check for error needed, because arguments are fixed.
	fs.Parse(args)
	// Ignore errors, only pass1 needs to check them.
	addConfigFromFile(path, fs)
	return cnf
}

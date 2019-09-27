package main

import (
	"fmt"
	"github.com/hknutzen/go-Netspoc/pkg/abort"
	"github.com/hknutzen/go-Netspoc/pkg/conf"
	"github.com/hknutzen/go-Netspoc/pkg/diag"
	"github.com/hknutzen/go-Netspoc/pkg/filetree"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

var globalType = map[string]bool{
	"router":          true,
	"network":         true,
	"host":            true,
	"any":             true,
	"group":           true,
	"area":            true,
	"service":         true,
	"owner":           true,
	"protocol":        true,
	"protocolgroup":   true,
	"pathrestriction": true,
	"nat":             true,
	"isakmp":          true,
	"ipsec":           true,
	"crypto":          true,
}

// NAT is applied with bind_nat.
// Owner is optionally referenced as sub_owner.
// Interface definition uses network name.
var aliases = map[string][]string{
	"nat":     {"bind_nat"},
	"owner":   {"sub_owner"},
	"network": {"interface"},
}

var subst = make(map[string]map[string]string)

// Fill subst with mapping from search to replace for given type.
func setupSubst(objType string, search string, replace string) {
	if !globalType[objType] {
		abort.Msg("Unknown type %s", objType)
	}
	addSubst := func(objType, search, replace string) {
		subMap, ok := subst[objType]
		if !ok {
			subMap = make(map[string]string)
			subst[objType] = subMap
		}
		subMap[search] = replace
	}

	addSubst(objType, search, replace)

	for _, other := range aliases[objType] {
		addSubst(other, search, replace)
	}
}

func substitute(objType string, name string) string {
	if objType == "host" && strings.HasPrefix(name, "id:") {
		// ID host is extended by network name: host:id:a.b@c.d.net_name
		parts := strings.Split(name, ".")
		network := parts[len(parts)-1]
		host := strings.Join(parts[:len(parts)-1], ".")
		if replace, ok := subst["host"][host]; ok {
			host = replace
			name = host + "." + network
		}
		if replace, ok := subst["network"][network]; ok {
			network = replace
			name = host + "." + network
		}
	} else if objType == "interface" && strings.Count(name, ".") > 0 {
		// Reference to interface ouside the definition of router.
		parts := strings.Split(name, ".")
		router := parts[0]
		network := parts[1]
		ext := ""
		if len(parts) > 2 {
			ext = "." + parts[2]
		}
		if replace, ok := subst["router"][router]; ok {
			router = replace
			name = router + "." + network + ext
		}
		if replace, ok := subst["network"][network]; ok {
			network = replace
			name = router + "." + network + ext
		}
	} else if replace, ok := subst[objType][name]; ok {
		return replace
	}
	return name
}

func process(input string) (int, string) {
	changed := 0
	typelist := ""
	copy := ""

	// Iteratively parse inputstring
	comment := regexp.MustCompile(`^\s*[#].*\n`)
	nothing := regexp.MustCompile(`^.*\n`)
	declaration := regexp.MustCompile(`^(.*?)(\w+)(:)([-\w\p{Ll}\p{Lu}.\@:]+)`)
	list := regexp.MustCompile(`^(.*?)([-\w]+)(\s*=[ \t]*)`)
	listelem := regexp.MustCompile(`^(\s*)([-\w\p{Ll}\p{Lu}.\@:]+)`)
	comma := regexp.MustCompile(`^\s*,\s*`)

	// Match pattern in input and skip matched pattern.
	match := func(pattern *regexp.Regexp) []string {
		matches := pattern.FindStringSubmatch(input)
		if matches == nil {
			return nil
		}
		skip := len(matches[0])
		input = input[skip:]
		return matches
	}

	for {
		if m := match(comment); m != nil {
			// Ignore comment.
			copy += m[0]
		} else if typelist != "" {
			// Handle list of names after "name = "
			// Read list element.
			if m := match(listelem); m != nil {
				copy += m[1]
				name := m[2]
				new := substitute(typelist, name)
				copy += new
				if new != name {
					changed++
				}
			} else if m := match(comma); m != nil {
				// Read comma.
				copy += m[0]
			} else {
				// Everything else terminates list.
				typelist = ""
			}
		} else if m := match(declaration); m != nil {
			// Find next "type:name".
			copy += m[1] + m[2] + m[3]
			objType := m[2]
			name := m[4]
			new := substitute(objType, name)
			copy += new
			if new != name {
				changed++
			}
		} else if m := match(list); m != nil {
			// Find "type = name".
			copy += m[1] + m[2] + m[3]
			objType := m[2]
			if subst[objType] != nil {
				typelist = m[2]
			}
		} else if m := match(nothing); m != nil {
			// Ignore rest of line if nothing matches.
			copy += m[0]
		} else {
			// Terminate, if everything has been processed.
			break
		}
	}
	return changed, copy
}

func processInput(input *filetree.Context) {
	count, copy := process(input.Data)
	if count == 0 {
		return
	}

	path := input.Path
	diag.Info("%d changes in %s", count, path)
	err := os.Remove(path)
	if err != nil {
		abort.Msg("Can't remove %s: %s", path, err)
	}
	file, err := os.Create(path)
	if err != nil {
		abort.Msg("Can't create %s: %s", path, err)
	}
	_, err = file.WriteString(copy)
	if err != nil {
		abort.Msg("Can't write to %s: %s", path, err)
	}
	file.Close()
}

func getTypeAndName(objName string) (string, string) {
	r := regexp.MustCompile(`^(\w+):(.*)$`)
	res := r.FindStringSubmatch(objName)
	if len(res) != 3 {
		abort.Msg("Missing type in '%s'", objName)
	}
	return res[1], res[2]
}

func setupPattern(pattern []string) {
	for len(pattern) > 0 {
		old := pattern[0]
		if len(pattern) < 2 {
			abort.Msg("Missing replace string for '%s'", old)
		}
		new := pattern[1]
		pattern = pattern[2:]

		oldType, oldName := getTypeAndName(old)
		newType, newName := getTypeAndName(new)
		if oldType != newType {
			abort.Msg("Types must be identical in\n - %s\n - %s", old, new)
		}
		setupSubst(oldType, oldName, newName)
	}
}

func readPattern(path string) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		abort.Msg("Can't %s", err)
	}
	pattern := strings.Fields(string(bytes))
	if len(pattern) == 0 {
		abort.Msg("Missing pattern in %s", path)
	}
	setupPattern(pattern)
}

func main() {

	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR SUBSTITUTION ...\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := pflag.StringP("file", "f", "", "Read pairs from file")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		os.Exit(1)
	}
	inPath := args[0]

	// Initialize search/replace pairs.
	if *fromFile != "" {
		readPattern(*fromFile)
	}
	if len(args) > 1 {
		setupPattern(args[1:])
	}
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, inPath)

	// Do substitution.
	filetree.Walk(inPath, processInput)
}

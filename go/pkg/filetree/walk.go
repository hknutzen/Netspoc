package filetree

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"os"
	"path"
	"path/filepath"
)

type Context struct {
	Path string
	Data string
	IPV6 bool
}
type parser func(*Context) error

// Read input from file and process it by function which is given as argument.
func processFile(fname string, v6 bool, fn parser) error {
	input := &Context{Path: fname, IPV6: v6}
	content, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	input.Data = string(content)
	return fn(input)
}

func Walk(fname string, fn parser) error {
	v6 := conf.Conf.IPV6
	ipvDir := "ipv6"
	if v6 {
		ipvDir = "ipv4"
	}
	ignore := conf.Conf.IgnoreFiles

	var walk func(string, bool, bool) error
	walk = func(fname string, v6, toplevel bool) error {
		base := path.Base(fname)

		// Skip hidden and ignored file.
		if base[0] == '.' || ignore.MatchString(base) {
			return nil
		}

		// Handle ipv6 / ipv4 subdirectory or file.
		if base == ipvDir {
			v6 = base == "ipv6"
		}

		if !fileop.IsDir(fname) {
			return processFile(fname, v6, fn)
		}
		files, err := os.ReadDir(fname)
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			base := file.Name()

			// Skip special file/directory.
			if toplevel && (base == "config" || base == "raw") {
				continue
			}
			name := filepath.Join(fname, base)
			if err := walk(name, v6, false); err != nil {
				return err
			}
		}
		return nil
	}
	toplevel := true
	return walk(fname, v6, toplevel)
}

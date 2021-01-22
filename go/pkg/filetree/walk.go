package filetree

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"io/ioutil"
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
func processFile(input *Context, fn parser) error {
	content, err := ioutil.ReadFile(input.Path)
	if err != nil {
		return err
	}
	input.Data = string(content)
	return fn(input)
}

func Walk(fname string, fn parser) error {
	v6 := conf.Conf.IPV6

	// Handle toplevel file.
	if !fileop.IsDir(fname) {
		input := &Context{Path: fname, IPV6: v6}
		return processFile(input, fn)
	}

	ipvDir := "ipv6"
	if conf.Conf.IPV6 {
		ipvDir = "ipv4"
	}
	ignore := conf.Conf.IgnoreFiles

	// Handle toplevel Directory
	files, err := ioutil.ReadDir(fname)
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		base := file.Name()

		// Skip special file/directory.
		if base == "config" || base == "raw" {
			continue
		}
		name := filepath.Join(fname, base)
		var walk func(string, bool) error
		walk = func(fname string, v6 bool) error {
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
				input := &Context{Path: fname, IPV6: v6}
				return processFile(input, fn)
			}
			files, err := ioutil.ReadDir(fname)
			if err != nil {
				panic(err)
			}
			for _, file := range files {
				base := file.Name()
				name := filepath.Join(fname, base)
				if err := walk(name, v6); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(name, v6); err != nil {
			return err
		}
	}
	return nil
}

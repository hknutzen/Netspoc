package filetree

import (
	"os"
	"path"
	"path/filepath"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
)

const ignore = "CVS"

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

func Walk(fname string, v6 bool, fn parser) error {
	var walk func(string, bool, bool) error
	walk = func(fname string, v6, toplevel bool) error {
		if !toplevel {
			base := path.Base(fname)

			// Skip hidden and ignored file.
			if base[0] == '.' || base == ignore {
				return nil
			}

			// Handle ipv6 / ipv4 subdirectory or file.
			switch base {
			case "ipv4":
				v6 = false
			case "ipv6":
				v6 = true
			}
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

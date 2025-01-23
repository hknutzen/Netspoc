package filetree

import (
	"os"
	"path"
	"path/filepath"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
)

type Context struct {
	Path string
	Data string
}
type parser func(*Context) error

// Read input from file and process it by function which is given as argument.
func processFile(fname string, fn parser) error {
	input := &Context{Path: fname}
	content, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	input.Data = string(content)
	return fn(input)
}

func Walk(fname string, fn parser) error {
	var walk func(string, bool) error
	walk = func(fname string, toplevel bool) error {
		if !toplevel {
			base := path.Base(fname)

			// Skip hidden file and editor backup file.
			if base[0] == '.' || base[len(base)-1] == '~' {
				return nil
			}

		}
		if !fileop.IsDir(fname) {
			return processFile(fname, fn)
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
			if err := walk(name, false); err != nil {
				return err
			}
		}
		return nil
	}
	toplevel := true
	return walk(fname, toplevel)
}

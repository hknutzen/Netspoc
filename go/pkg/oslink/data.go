package oslink

import (
	"io"
	"os"
)

type Data struct {
	Args     []string
	Stdout   io.Writer
	Stderr   io.Writer
	ShowDiag bool
}

func Get() Data {
	return Data{
		Args:     os.Args,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		ShowDiag: os.Getenv("SHOW_DIAG") != "",
	}
}

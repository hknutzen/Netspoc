package capture

import (
	"bytes"
	"io"
	"os"
)

func Capture(std **os.File, f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	old := *std
	*std = w
	defer func() {
		*std = old
	}()

	out := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		out <- buf.String()
	}()

	f()

	w.Close()
	return <-out
}

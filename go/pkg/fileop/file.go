package fileop

import (
	"fmt"
	"os"
)

func IsDir(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.Mode().IsDir()
}

func IsRegular(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.Mode().IsRegular()
}

func Readdirnames(path string) []string {
	fh, e := os.Open(path)
	if e != nil {
		panic(e)
	}
	defer fh.Close()
	list, e := fh.Readdirnames(0)
	if e != nil {
		panic(e)
	}
	return list
}

func Overwrite(path string, data []byte) error {
	os.Remove(path) // Ignore error
	fd, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Can't %v", err)
	}
	defer fd.Close()
	_, err = fd.Write(data)
	if err != nil {
		return fmt.Errorf("Can't %v", err)
	}
	return nil
}

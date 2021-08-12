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
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("Can't %v", err)
	}
	return nil
}

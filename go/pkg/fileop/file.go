package fileop

import (
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
	list, e := fh.Readdirnames(0)
	if e != nil {
		panic(e)
	}
	return list
}

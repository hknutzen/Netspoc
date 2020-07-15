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
	list, e := fh.Readdirnames(0)
	if e != nil {
		panic(e)
	}
	return list
}

func Overwrite(path string, data []byte) error {
	err := os.Remove(path)
	if err != nil {
		return fmt.Errorf("Can't remove %v: %v", path, err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Can't create %v: %v", path, err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("Can't write to %v: %v", path, err)
	}
	return nil
}

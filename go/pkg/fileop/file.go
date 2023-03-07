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

func Overwrite(path string, data []byte) error {
	err := os.WriteFile(path, data, 0666)
	if err != nil {
		return fmt.Errorf("Can't %v", err)
	}
	return nil
}

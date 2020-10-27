package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"
)

// Copy raw configuration files of devices into outDir for devices
// known from topology.
func (c *spoc) copyRaw1(rawDir, outDir, ignoreDir string) {
	ipV6 := strings.HasSuffix(outDir, "/ipv6")
	deviceNames := make(map[string]bool)
	for _, r := range append(c.managedRouters, c.routingOnlyRouters...) {
		if r.ipV6 == ipV6 {
			deviceNames[r.deviceName] = true
		}
	}

	// outDir has already been checked / created in printCode.
	files, err := ioutil.ReadDir(rawDir)
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		base := file.Name()
		ignore := conf.Conf.IgnoreFiles
		if base[0] == '.' || ignore.MatchString(base) || base == ignoreDir {
			continue
		}
		rawPath := filepath.Join(rawDir, base)
		if !fileop.IsRegular(rawPath) {
			c.warn("Ignoring path " + rawPath)
			continue
		}
		if _, found := deviceNames[base]; !found {
			c.warn("Found unused file " + rawPath)
			continue
		}
		dest := filepath.Join(outDir, base)
		dest += ".raw"
		cmd := exec.Command("cp", "-f", rawPath, dest)
		err := cmd.Run()
		if err != nil {
			c.abort("Can't %v", err)
		}
	}
}

func (c *spoc) copyRaw(inPath, outDir string) {
	rawDir := filepath.Join(inPath, "raw")
	if !fileop.IsDir(rawDir) {
		return
	}
	outV6 := filepath.Join(outDir, "ipv6")
	if conf.Conf.IPV6 {
		c.copyRaw1(rawDir, outV6, "ipv4")
		subDir := filepath.Join(rawDir, "ipv4")
		if fileop.IsDir(subDir) {
			c.copyRaw1(subDir, outDir, "")
		}
	} else {
		c.copyRaw1(rawDir, outDir, "ipv6")
		subDir := filepath.Join(rawDir, "ipv6")
		if fileop.IsDir(subDir) {
			c.copyRaw1(subDir, outV6, "")
		}
	}
}

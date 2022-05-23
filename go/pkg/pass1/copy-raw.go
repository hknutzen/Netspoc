package pass1

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
)

// Copy raw configuration files of devices into outDir for devices
// known from topology.
func (c *spoc) copyRaw1(rawDir, outDir, ignoreDir string) {
	ipV6 := strings.HasSuffix(outDir, "/ipv6")
	deviceNames := make(map[string]bool)
	for _, r := range c.managedRouters {
		if r.ipV6 == ipV6 {
			deviceNames[r.deviceName] = true
		}
	}

	// outDir has already been checked / created in printCode.
	files, err := os.ReadDir(rawDir)
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		base := file.Name()
		ignore := c.conf.IgnoreFiles
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
		if out, err := cmd.CombinedOutput(); err != nil {
			c.abort("Can't cp %s to %s: %v\n%s", rawPath, dest, err, out)
		}
	}
}

func (c *spoc) copyRaw(inPath, outDir string) {
	rawDir := filepath.Join(inPath, "raw")
	if !fileop.IsDir(rawDir) {
		return
	}
	outV6 := filepath.Join(outDir, "ipv6")
	if c.conf.IPV6 {
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

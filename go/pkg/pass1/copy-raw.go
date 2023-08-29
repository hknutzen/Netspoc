package pass1

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
)

// Copy raw configuration files of devices into outDir for devices
// known from topology.
func (c *spoc) copyRaw(inPath, outDir string) {
	rawDir := filepath.Join(inPath, "raw")
	if !fileop.IsDir(rawDir) {
		return
	}
	deviceNames := make(map[string]bool)
	for _, r := range c.managedRouters {
		deviceNames[r.deviceName] = true
	}

	// outDir has already been checked / created in printCode.
	files, err := os.ReadDir(rawDir)
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		base := file.Name()
		if base[0] == '.' || base == filetree.Ignore {
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

package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
)

func (c *spoc) checkUnusedGroups() {
	c = c.sortingSpoc()
	if printType := conf.Conf.CheckUnusedGroups; printType != "" {
		for _, group := range symTable.group {
			if !group.isUsed {
				c.warnOrErr(printType, "unused "+group.name)
			}
		}
		for _, group := range symTable.protocolgroup {
			if !group.isUsed {
				c.warnOrErr(printType, "unused "+group.name)
			}
		}
	}
	if printType := conf.Conf.CheckUnusedProtocols; printType != "" {
		for _, prt := range symTable.protocol {
			if !prt.isUsed {
				c.warnOrErr(printType, "unused "+prt.name)
			}
		}
	}
	c.finish()

	// Not used any longer; free memory.
	symTable.group = nil
}

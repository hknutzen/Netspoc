package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
)

func (c *spoc) checkUnusedGroups() {
	c.sortedSpoc(func(c *spoc) {
		if printType := conf.Conf.CheckUnusedGroups; printType != "" {
			for _, group := range symTable.group {
				if !group.isUsed {
					c.warnOrErr(printType, "unused %s", group)
				}
			}
			for _, group := range symTable.protocolgroup {
				if !group.isUsed {
					c.warnOrErr(printType, "unused %s", group.name)
				}
			}
		}
		if printType := conf.Conf.CheckUnusedProtocols; printType != "" {
			for _, prt := range symTable.protocol {
				if !prt.isUsed {
					c.warnOrErr(printType, "unused %s", prt.name)
				}
			}
		}
	})

	// Not used any longer; free memory.
	symTable.group = nil
}

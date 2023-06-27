package pass1

func (c *spoc) checkUnused() {
	c.sortedSpoc(func(c *spoc) {
		if printType := c.conf.CheckUnusedGroups; printType != "" {
			for _, group := range c.symTable.group {
				if !group.isUsed {
					c.warnOrErr(printType, "unused %s", group)
				}
			}
			for _, group := range c.symTable.protocolgroup {
				if !group.isUsed {
					c.warnOrErr(printType, "unused %s", group.name)
				}
			}
		}
		if printType := c.conf.CheckUnusedOwners; printType != "" {
			for _, o := range c.symTable.owner {
				if !o.isUsed {
					c.warnOrErr(printType, "Unused %s", o)
				}
			}
		}
		if printType := c.conf.CheckUnusedProtocols; printType != "" {
			for _, prt := range c.symTable.protocol {
				if !prt.isUsed {
					c.warnOrErr(printType, "unused %s", prt.name)
				}
			}
		}
	})

	// Not used any longer; free memory.
	c.symTable.group = nil
}

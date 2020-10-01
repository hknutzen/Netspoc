package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"sort"
)

func CheckUnusedGroups() {
	if printType := conf.Conf.CheckUnusedGroups; printType != "" {
		// Check groups
		names := make([]string, 0, len(symTable.group))
		for name := range symTable.group {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			group := symTable.group[name]
			if !group.isUsed {
				warnOrErrMsg(printType, "unused "+group.name)
			}
		}
		// Check protocolGroups
		names = names[:0]
		for name := range symTable.protocolgroup {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			group := symTable.protocolgroup[name]
			if !group.isUsed {
				warnOrErrMsg(printType, "unused "+group.name)
			}
		}
	}
	if printType := conf.Conf.CheckUnusedProtocols; printType != "" {
		names := make([]string, 0, len(symTable.protocol))
		for name := range symTable.protocol {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			prt := symTable.protocol[name]
			if !prt.isUsed {
				warnOrErrMsg(printType, "unused "+prt.name)
			}
		}
	}

	// Not used any longer; free memory.
	symTable.group = nil
}

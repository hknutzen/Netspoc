package pass1

import (
	"sort"
)

func CheckUnusedGroups() {
	if printType := config.CheckUnusedGroups; printType != "0" {
		// Check groups
		names := make([]string, 0, len(groups))
		for name := range groups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			group := groups[name]
			if !group.isUsed {
				warnOrErrMsg(printType, "unused "+group.name)
			}
		}
		// Check protocolGroups
		names = names[:0]
		for name := range protocolGroups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			group := protocolGroups[name]
			if !group.isUsed {
				warnOrErrMsg(printType, "unused "+group.name)
			}
		}
	}
	if printType := config.CheckUnusedProtocols; printType != "0" {
		names := make([]string, 0, len(protocols))
		for name := range protocols {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			prt := protocols[name]
			if !prt.isUsed {
				warnOrErrMsg(printType, "unused "+prt.name)
			}
		}
	}

	// Not used any longer; free memory.
	groups = nil
}

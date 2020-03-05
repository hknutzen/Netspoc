package pass1

// Combine different natSets into a single natSet in a way
// that NAT mapping remains mostly identical.
// Single NAT tags remain active if they are active in all sets.
// Different real NAT tags of a multi NAT set can't be combined.
// In this case NAT is disabled for this multi NAT set.
// Hidden NAT tag is ignored if combined with a real NAT tag,
// because hidden tag doesn't affect address calculation.
// Multiple hidden tags without real tag are ignored.
func combineNatSets(sets []natSet, natTag2multinatDef map[string][]natMap, natTag2natType map[string]string) natSet {
	if len(sets) == 1 {
		return sets[0]
	}

	// Collect single NAT tags and multi NAT hashes.
	combined := make(map[string]bool)
	var activeMulti []map[string]*network
	seen := make(map[string]bool)
	for _, set := range sets {
		for tag, _ := range *set {
			if seen[tag] {
				continue
			}
			if list := natTag2multinatDef[tag]; list != nil {
				for _, multiNatMap := range list {
					for tag, _ := range multiNatMap {
						seen[tag] = true
					}
					activeMulti = append(activeMulti, multiNatMap)
				}
			} else {
				combined[tag] = true
			}
		}
	}

	// Build intersection for NAT tags of all sets.
	activeMultiSets := make([]map[string]bool, len(activeMulti))
	for i, _ := range activeMultiSets {
		activeMultiSets[i] = make(map[string]bool)
	}
	for _, set := range sets {
		for tag, _ := range combined {
			if (*set)[tag] {
				continue
			}
			if natTag2multinatDef[tag] != nil {
				continue
			}
			delete(combined, tag)
		}
		for i, multiNatMap := range activeMulti {
			var active string
			for tag, _ := range multiNatMap {
				if (*set)[tag] {
					active = tag
					break
				}
			}
			if active == "" {
				active = ":none"
			}
			activeMultiSets[i][active] = true
		}
	}

	// Process multi NAT tags.
	// Collect to be added and to be ignored tags.
	ignore := make(map[string]bool)
	toAdd := make(map[string]bool)
	for _, m := range activeMultiSets {
		var add string

		// Analyze active and inactive tags.
		if !m[":none"] {
			var realTag string
			for tag, _ := range m {
				if natTag2natType[tag] != "hidden" {
					if realTag != "" {

						// Ignore multiple real tags.
						realTag = ""
						break
					}
					realTag = tag
				}
			}
			if realTag != "" {

				// Add single real tag with ignored hidden tags.
				add = realTag
			}
			// Ignore multiple hidden tags.
		}
		if add != "" {
			toAdd[add] = true
		} else {

			// Ignore all tags, if none is active.
			add = ":none"
		}

		// Tag that is ignored in one multi set must be ignored completely.
		for tag, _ := range m {
			if tag == add {
				continue
			}
			ignore[tag] = true
		}
	}
	for tag, _ := range toAdd {
		if ignore[tag] {
			continue
		}
		combined[tag] = true
	}
	return &combined
}

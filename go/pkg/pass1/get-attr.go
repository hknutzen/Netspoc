package pass1

const (
	overlapsAttr = iota
	identicalBodyAttr
	unknownOwnerAttr
	multiOwnerAttr
	hasUnenforceableAttr
	maxAttr
)

const (
	unsetVal = iota
	enableVal
	restrictVal
	okVal
)

type attrKey int
type attrVal byte
type attrStore [maxAttr]attrVal

func getAttrFromArea(k attrKey, obj *area) attrVal {
	if v := obj.attr[k]; v != unsetVal {
		return v
	}
	if a := obj.inArea; a != nil {
		v := getAttrFromArea(k, a)
		obj.attr[k] = v
		return v
	}
	return enableVal
}

func getAttrFromZone(k attrKey, obj *zone) attrVal {
	if v := obj.attr[k]; v != unsetVal {
		return v
	}
	if a := obj.inArea; a != nil {
		v := getAttrFromArea(k, a)
		obj.attr[k] = v
		return v
	}
	return enableVal
}

func getAttrFromNetwork(k attrKey, obj *network) attrVal {
	if v := obj.attr[k]; v != unsetVal {
		return v
	}
	if up := obj.up; up != nil {
		v := getAttrFromNetwork(k, up)
		obj.attr[k] = v
		return v
	}
	v := getAttrFromZone(k, obj.zone)
	obj.attr[k] = v
	return v
}

func (obj *network) getAttr(k attrKey) attrVal {
	return getAttrFromNetwork(k, obj)
}
func (obj *subnet) getAttr(k attrKey) attrVal {
	return getAttrFromNetwork(k, obj.network)
}
func (obj *host) getAttr(k attrKey) attrVal {
	return getAttrFromNetwork(k, obj.network)
}
func (obj *routerIntf) getAttr(k attrKey) attrVal {
	return getAttrFromNetwork(k, obj.network)
}

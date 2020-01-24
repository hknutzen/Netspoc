package pass1

func getAttrFromArea(attr string, obj *area) string {
	if v, ok := obj.attr[attr]; ok {
		return v
	}
	if a := obj.inArea; a != nil {
		v := getAttrFromArea(attr, a)
		if obj.attr == nil {
			obj.attr = make(map[string]string)
		}
		obj.attr[attr] = v
		return v
	}
	return ""
}

func getAttrFromZone(attr string, obj *zone) string {
	if v, ok := obj.attr[attr]; ok {
		return v
	}
	if a := obj.inArea; a != nil {
		v := getAttrFromArea(attr, a)
		if obj.attr == nil {
			obj.attr = make(map[string]string)
		}
		obj.attr[attr] = v
		return v
	}
	return ""
}

func getAttrFromNetwork(attr string, obj *network) string {
	if v, ok := obj.attr[attr]; ok {
		return v
	}
	if up := obj.up; up != nil {
		v := getAttrFromNetwork(attr, up)
		if obj.attr == nil {
			obj.attr = make(map[string]string)
		}
		obj.attr[attr] = v
		return v
	}
	zone := obj.zone
	v := getAttrFromZone(attr, zone)
	if obj.attr == nil {
		obj.attr = make(map[string]string)
	}
	obj.attr[attr] = v
	return v
}

func (obj *network) getAttr(attr string) string {
	return getAttrFromNetwork(attr, obj)
}
func (obj *subnet) getAttr(attr string) string {
	return getAttrFromNetwork(attr, obj.network)
}
func (obj *host) getAttr(attr string) string {
	return getAttrFromNetwork(attr, obj.network)
}
func (obj *routerIntf) getAttr(attr string) string {
	return getAttrFromNetwork(attr, obj.network)
}

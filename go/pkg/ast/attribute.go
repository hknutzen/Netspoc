package ast

import (
	"sort"
)

func CreateAttr1(k, v string) *Attribute {
	return CreateAttr(k, []string{v})
}

func CreateAttr(name string, l []string) *Attribute {
	sort.Strings(l)
	vl := make([]*Value, len(l))
	for i, part := range l {
		vl[i] = &Value{Value: part}
	}
	return &Attribute{Name: name, ValueList: vl}
}

func (n *TopStruct) GetAttr1(name string) string {
	for _, a := range n.Attributes {
		if a.Name == name {
			l := a.ValueList
			if len(l) > 0 {
				return l[0].Value
			}
		}
	}
	return ""
}

func (n *TopStruct) GetAttr(name string) *Attribute {
	for _, a := range n.Attributes {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func (obj *Attribute) Remove(name string) {
	if obj.ValueList != nil {
		cp := make([]*Value, 0, len(obj.ValueList))
		for _, a := range obj.ValueList {
			if a.Value != name {
				cp = append(cp, a)
			}
		}
		obj.ValueList = cp
	} else {
		cp := make([]*Attribute, 0, len(obj.ComplexValue)-1)
		for _, a := range obj.ComplexValue {
			if a.Name != name {
				cp = append(cp, a)
			}
		}
		obj.ComplexValue = cp
	}
}

func (obj *Attribute) Replace(attr *Attribute) {
	for i, a := range obj.ComplexValue {
		if a.Name == attr.Name {
			obj.ComplexValue[i] = attr
			return
		}
	}
	obj.ComplexValue = append(obj.ComplexValue, attr)
}

func (obj *Attribute) Change(name, value string) {
	if value == "" {
		obj.Remove(name)
		return
	}
	attr := &Attribute{
		Name:      name,
		ValueList: []*Value{{Value: value}},
	}
	obj.Replace(attr)
}

func (obj *TopStruct) RemoveAttr(name string) {
	cp := make([]*Attribute, 0, len(obj.Attributes)-1)
	for _, a := range obj.Attributes {
		if a.Name != name {
			cp = append(cp, a)
		}
	}
	obj.Attributes = cp
}

func (obj *TopStruct) ReplaceAttr(attr *Attribute) {
	for i, a := range obj.Attributes {
		if a.Name == attr.Name {
			obj.Attributes[i] = attr
			return
		}
	}
	obj.Attributes = append(obj.Attributes, attr)
}

func (obj *TopStruct) ChangeAttr(name string, l []string) {
	if l == nil {
		return
	} else if len(l) == 0 {
		obj.RemoveAttr(name)
		return
	}

	attr := new(Attribute)
	attr.Name = name
	sort.Strings(l)
	for _, part := range l {
		v := new(Value)
		v.Value = part
		attr.ValueList = append(attr.ValueList, v)
	}
	obj.ReplaceAttr(attr)
}

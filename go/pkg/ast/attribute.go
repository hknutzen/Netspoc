package ast

import "slices"

func CreateAttr1(k, v string) *Attribute {
	return CreateAttr(k, []string{v})
}

func CreateAttr(name string, l []string) *Attribute {
	slices.Sort(l)
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
			if len(l) != 0 {
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

func (n *TopStruct) GetAttributes() []*Attribute {
	return n.Attributes
}

func (obj *Attribute) GetAttr(name string) *Attribute {
	for _, a := range obj.ComplexValue {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func (obj *Attribute) RemoveFromList(name string) {
	cp := make([]*Value, 0, len(obj.ValueList))
	for _, a := range obj.ValueList {
		if a.Value != name {
			cp = append(cp, a)
		}
	}
	obj.ValueList = cp
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

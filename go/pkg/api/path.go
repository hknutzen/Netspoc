package api

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
)

type change struct {
	method     string
	okIfExists bool
	val        interface{}
}

func (s *state) patch(j *job) error {
	var p struct {
		Path       string
		Value      interface{}
		OkIfExists bool `json:"ok_if_exists"`
		IPV6       *bool
	}
	getParams(j, &p)
	c := change{val: p.Value, okIfExists: p.OkIfExists}
	c.method = j.Method

	if len(p.Path) == 0 {
		return fmt.Errorf("Invalid empty path")
	}
	names := strings.Split(p.Path, ",")
	// Find toplevel node
	topName := names[0]
	names = names[1:]
	var top ast.Toplevel
	isRouter := strings.HasPrefix(topName, "router:")
	ipv6 := p.IPV6 != nil && *p.IPV6 || s.IPV6
	s.Modify(func(t ast.Toplevel) bool {
		if t.GetName() == topName && (!isRouter || t.GetIPV6() == ipv6) {
			top = t
			return true // Mark as modified.
		}
		return false
	})
	if top == nil {
		if len(names) == 0 {
			return s.addToplevel(topName, ipv6, c)
		}
		if isRouter {
			ipvx := "IPv4"
			if ipv6 {
				ipvx = "IPv6"
			}
			return fmt.Errorf("Can't modify unknown %s '%s'", ipvx, topName)
		}
		return fmt.Errorf("Can't modify unknown toplevel object '%s'", topName)
	}
	process := func() error {
		if len(names) == 0 {
			return s.patchToplevel(top, c)
		}
		name := names[0]
		var ts *ast.TopStruct
		switch x := top.(type) {
		case *ast.TopList:
			switch name {
			case "elements":
				return patchElemList(&x.Elements, names[1:], c)
			case "description":
				return patchDescription(&x.TopBase, names, c)
			default:
				return fmt.Errorf("Expected attribute 'elements'")
			}
		case *ast.Network:
			if strings.HasPrefix(name, "host:") {
				return patchAttributes(&x.Hosts, names, c)
			}
			ts = &x.TopStruct
		case *ast.Router:
			if strings.HasPrefix(name, "interface:") {
				return patchAttributes(&x.Interfaces, names, c)
			}
			ts = &x.TopStruct
		case *ast.Service:
			if name == "user" {
				return patchElemList(&x.User.Elements, names[1:], c)
			}
			if name == "rules" {
				return patchRules(&x.Rules, names[1:], c)
			}
			ts = &x.TopStruct
		case *ast.Area:
			if name == "border" {
				return patchElemList(&x.Border.Elements, names[1:], c)
			}
			if name == "inclusive_border" {
				return patchElemList(&x.InclusiveBorder.Elements, names[1:], c)
			}
			ts = &x.TopStruct
		case *ast.TopStruct:
			ts = x
		}
		return patchTopStruct(ts, names, c)
	}
	err := process()
	if err == nil {
		top.Order()
	}
	return err
}

func patchRules(l *[]*ast.Rule, names []string, c change) error {
	if len(names) == 0 {
		return newRule(l, c)
	}
	name := names[0]
	// Expect "<rule_num>" or "<rule_num>/<rule_count>".
	if ruleNum, count, found := strings.Cut(name, "/"); found {
		c, err := strconv.Atoi(count)
		if err != nil {
			return fmt.Errorf("Number expected after '/' in '%s'", name)
		}
		if c != len(*l) {
			return fmt.Errorf("rule count %d doesn't match, having %d rules",
				c, len(*l))
		}
		name = ruleNum
	}
	num, err := strconv.Atoi(name)
	if err != nil {
		return fmt.Errorf("Number expected in '%s'", name)
	}
	if num > len(*l) {
		return fmt.Errorf("rule num %d is larger than number of rules: %d",
			num, len(*l))
	}
	if num < 1 {
		return fmt.Errorf("Invalid rule num %d; first rule has number 1", num)
	}
	idx := num - 1
	rule := (*l)[idx]
	names = names[1:]
	if len(names) == 0 {
		if c.method == "delete" {
			*l = append((*l)[:idx], (*l)[idx+1:]...)
			return nil
		}
		return fmt.Errorf("Attribute of rule must be given for '%s'", c.method)
	}
	name = names[0]
	if c.val == nil {
		return fmt.Errorf("Missing value to modify in '%s' of rule", name)
	}
	switch name {
	case "src":
		return patchElemList(&rule.Src.Elements, names[1:], c)
	case "dst":
		return patchElemList(&rule.Dst.Elements, names[1:], c)
	case "prt":
		return patchAttributes(&[]*ast.Attribute{rule.Prt}, names, c)
	case "log":
		if rule.Log != nil {
			return patchAttributes(&[]*ast.Attribute{rule.Log}, names, c)
		}
		var l []*ast.Attribute
		err := patchAttributes(&l, names, c)
		if err == nil {
			rule.Log = l[0]
		}
		return err
	}
	return fmt.Errorf("Invalid attribute in rule: '%s'", name)
}

func newRule(l *[]*ast.Rule, c change) error {
	if c.method != "add" {
		return fmt.Errorf("Rule number must be given for '%s'", c.method)
	}
	rule, err := getRuleDef(c.val)
	if err != nil {
		return err
	}
	if rule.Deny {
		// Append in front after existing deny rules.
		cp := make([]*ast.Rule, len(*l)+1)
		pos := len(*l)
		for i, r := range *l {
			if !r.Deny {
				pos = i
				break
			}
		}
		copy(cp, (*l)[:pos])
		cp[pos] = rule
		copy(cp[pos+1:], (*l)[pos:])
		*l = cp
	} else {
		*l = append(*l, rule)
	}
	return nil
}

func patchTopStruct(ts *ast.TopStruct, names []string, c change) error {
	if names[0] == "description" {
		return patchDescription(&ts.TopBase, names, c)
	}
	return patchAttributes(&ts.Attributes, names, c)
}

func patchDescription(tb *ast.TopBase, names []string, c change) error {
	names = names[1:]
	if len(names) != 0 {
		return fmt.Errorf("Can't descend into value of 'description'")
	}
	old := ""
	if tb.Description != nil {
		old = tb.Description.Text
	}
	switch c.method {
	case "delete":
		tb.Description = nil
	case "add":
		if old != "" {
			return fmt.Errorf("Can't add to description")
		}
		fallthrough
	case "set":
		d, ok := c.val.(string)
		if !ok {
			return fmt.Errorf("Expecting string as description")
		}
		tb.Description = &ast.Description{Text: d}
	}
	return nil
}

func patchAttributes(l *[]*ast.Attribute, names []string, c change) error {
	name := names[0]
	names = names[1:]
	for i, a := range *l {
		if a.Name == name {
			if len(names) != 0 {
				if len(a.ComplexValue) == 0 {
					return fmt.Errorf("Can't descend into value of '%s'", a.Name)
				}
				return patchAttributes(&a.ComplexValue, names, c)
			}
			if c.val != nil {
				return patchValue(a, names, c)
			}
			if c.method == "delete" {
				*l = append((*l)[:i], (*l)[i+1:]...)
				return nil
			}
			return fmt.Errorf("Missing value to %s at '%s'", c.method, a.Name)
		}
	}
	return newAttribute(l, name, c)
}

func patchValue(a *ast.Attribute, names []string, c change) error {
	if c.method == "set" ||
		c.method == "add" && len(a.ComplexValue) == 0 && len(a.ValueList) == 0 {

		return setAttrValue(a, c.val)
	}
	if a.ComplexValue != nil {
		if c.method == "add" {
			return fmt.Errorf("Can't add to complex value of '%s'", a.Name)
		}
		return fmt.Errorf("Can't delete from complex value of '%s'", a.Name)
	}
	l, err := getValueList(c.val)
	if err != nil {
		return err
	}
	if c.method == "add" {
		a.ValueList = append(a.ValueList, l...)
		return nil
	}
	var cmp func(v1, v2 string) bool
	switch a.Name {
	default:
		cmp = func(v1, v2 string) bool { return v1 == v2 }
	case "prt", "general_permit":
		cmp = func(v1, v2 string) bool {
			// "icmp 3 / 13" and "icmp 3/13" should be recognized as equal.
			return strings.ReplaceAll(v1, " ", "") ==
				strings.ReplaceAll(v2, " ", "")
		}
	}
VAL:
	for _, v2 := range l {
		val2 := v2.Value
		for i, v := range a.ValueList {
			val := v.Value
			if cmp(val, val2) {
				// delete found element
				a.ValueList = append(a.ValueList[:i], a.ValueList[i+1:]...)
				continue VAL
			}
		}
		return fmt.Errorf("Can't find value '%s'", val2)
	}
	return nil
}

func getValueList(val interface{}) ([]*ast.Value, error) {
	a := &ast.Attribute{}
	if err := setAttrValue(a, val); err != nil {
		return nil, err
	}
	if a.ComplexValue != nil {
		return nil, fmt.Errorf("Expecting value list, not complex value")
	}
	return a.ValueList, nil
}

func newAttribute(l *[]*ast.Attribute, name string, c change) error {
	if c.method == "delete" {
		return fmt.Errorf("Can't delete unknown attribute '%s'", name)
	}
	// "add" and "set" behave identical on new attribute.
	a := &ast.Attribute{Name: name}
	if err := setAttrValue(a, c.val); err != nil {
		return err
	}
	*l = append(*l, a)
	return nil
}

func (s *state) addToplevel(name string, ipv6 bool, c change) error {
	if c.method == "delete" {
		return fmt.Errorf("Can't %s unknown toplevel node '%s'", c.method, name)
	}
	// "add" and "set" behave identical on new toplevel node.
	a, err := s.getToplevel(name, c)
	if err != nil {
		return err
	}
	s.AddTopLevel(a, ipv6)
	return nil
}

func (s *state) getToplevel(name string, c change) (ast.Toplevel, error) {
	m, ok := c.val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf(
			"Expecting JSON object when reading '%s' but got: %T", name, c.val)
	}
	var t ast.Toplevel
	var err error
	typ, _, _ := strings.Cut(name, ":")
	switch typ {
	case "service":
		t, err = getService(name, m)
	case "group", "pathrestriction":
		t, err = getTopList(name, m)
	default:
		var ts *ast.TopStruct
		ts, err = getTopStruct(name, m)
		if err != nil {
			return nil, err
		}
		switch typ {
		case "network":
			n := new(ast.Network)
			n.Name = name
			l := removeAttrFrom(ts, "host:")
			n.TopStruct = *ts
			n.Hosts = l
			t = n
		case "router":
			r := new(ast.Router)
			r.Name = name
			l := removeAttrFrom(ts, "interface:")
			r.TopStruct = *ts
			r.Interfaces = l
			t = r
		default:
			t = ts
		}
	}
	if err != nil {
		return nil, err
	}
	t.Order()
	return t, nil
}

func removeAttrFrom(ts *ast.TopStruct, prefix string) []*ast.Attribute {
	var removed []*ast.Attribute
	j := 0
	for _, a := range ts.Attributes {
		if strings.HasPrefix(a.Name, prefix) {
			removed = append(removed, a)
		} else {
			ts.Attributes[j] = a
			j++
		}
	}
	ts.Attributes = ts.Attributes[:j]
	return removed
}

func (s *state) patchToplevel(n ast.Toplevel, c change) error {
	if c.method == "delete" {
		s.DeleteToplevelNode(n)
		return nil
	}
	if c.method == "set" {
		a, err := s.getToplevel(n.GetName(), c)
		if err != nil {
			return err
		}
		s.Replace(func(ptr *ast.Toplevel) bool {
			if *ptr == n {
				*ptr = a
				return true
			}
			return false
		})
		return nil
	}
	if c.okIfExists {
		return nil
	}
	return fmt.Errorf("'%s' already exists", n.GetName())
}

func getTopList(name string, m map[string]interface{}) (ast.Toplevel, error) {
	elements, found := m["elements"]
	if !found {
		return nil, fmt.Errorf("Missing attribute 'elements' in '%s'", name)
	}
	delete(m, "elements")
	ts, err := getTopStruct(name, m)
	if err != nil {
		return nil, err
	}
	if len(ts.Attributes) > 0 {
		return nil, fmt.Errorf("Unexpected attribute '%s' in '%s'",
			ts.Attributes[0].Name, name)
	}
	tl := new(ast.TopList)
	tl.Name = name
	tl.TopBase = ts.TopBase
	tl.Elements, err = getElementList(elements)
	if err != nil {
		return nil, err
	}
	return tl, nil
}

func getService(name string, m map[string]interface{}) (ast.Toplevel, error) {
	user, found := m["user"]
	if !found {
		return nil, fmt.Errorf("Missing attribute 'user' in '%s'", name)
	}
	delete(m, "user")
	rules, found := m["rules"]
	if !found {
		return nil, fmt.Errorf("Missing attribute 'rules' in '%s'", name)
	}
	delete(m, "rules")
	s := new(ast.Service)
	t, err := getTopStruct(name, m)
	if err != nil {
		return nil, err
	}
	s.TopStruct = *t
	s.User, err = getNamedUnion("user", user)
	if err != nil {
		return nil, err
	}
	l, ok := rules.([]interface{})
	if !ok {
		return nil, fmt.Errorf(
			"Expecting JSON array after 'rules' but got: %T", rules)
	}
	for _, v := range l {
		rule, err := getRuleDef(v)
		if err != nil {
			return nil, err
		}
		s.Rules = append(s.Rules, rule)
	}
	return s, nil
}

func getRuleDef(v interface{}) (*ast.Rule, error) {
	obj, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Unexpected type when reading rule: %T", v)
	}
	expected := 4
	if _, found := obj["log"]; found {
		expected++
	}
	if len(obj) != expected {
		return nil, fmt.Errorf(
			`Rule needs keys "action", "src", "dst", "prt" and optional "log"`)
	}
	rule := new(ast.Rule)
	for key, val := range obj {
		var err error
		switch key {
		case "action":
			s, _ := val.(string)
			switch s {
			case "permit":
			case "deny":
				rule.Deny = true
			default:
				err = fmt.Errorf("Expected 'permit' or 'deny' in '%s'", key)
			}
		case "src":
			rule.Src, err = getNamedUnion(key, val)
		case "dst":
			rule.Dst, err = getNamedUnion(key, val)
		case "prt":
			rule.Prt, err = getAttribute(key, val)
		case "log":
			rule.Log, err = getAttribute(key, val)
		default:
			err = fmt.Errorf("Unexpected key '%s' in rule", key)
		}
		if err != nil {
			return nil, err
		}
	}
	return rule, nil
}

func getTopStruct(
	name string, m map[string]interface{}) (*ast.TopStruct, error) {

	t := new(ast.TopStruct)
	t.Name = name
	if val, found := m["description"]; found {
		delete(m, "description")
		d, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("Expecting string as description")
		}
		t.Description = &ast.Description{Text: d}
	}
	a, err := getAttribute(name, m)
	if err != nil {
		return nil, err
	}
	t.Attributes = a.ComplexValue
	return t, nil
}

func getAttribute(name string, v interface{}) (*ast.Attribute, error) {
	a := &ast.Attribute{Name: name}
	switch x := v.(type) {
	case nil:
	case string:
		a.ValueList = []*ast.Value{&ast.Value{Value: x}}
	case []interface{}:
		for _, v := range x {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("Unexpected type in JSON array: %T", v)
			}
			a.ValueList = append(a.ValueList, &ast.Value{Value: s})
		}
	case map[string]interface{}:
		keys := maps.Keys(x)
		sort.Strings(keys)
		var l []*ast.Attribute
		for _, k := range keys {
			attr, err := getAttribute(k, x[k])
			if err != nil {
				return nil, err
			}
			l = append(l, attr)
		}
		a.ComplexValue = l
	default:
		return nil, fmt.Errorf("Unexpected type in JSON value: %T", v)
	}
	return a, nil
}

func setAttrValue(a *ast.Attribute, val interface{}) error {
	a2, err := getAttribute(a.Name, val)
	if err != nil {
		return err
	}
	a.ValueList = a2.ValueList
	a.ComplexValue = a2.ComplexValue
	return nil
}

func patchElemList(l *[]ast.Element, names []string, c change) error {
	if len(names) != 0 {
		return fmt.Errorf("Can't descend into element list")
	}
	elements, err := getElementList(c.val)
	if err != nil {
		return err
	}
	if c.method != "delete" {
		if c.method == "add" {
			*l = append(*l, elements...)
		} else {
			*l = elements
		}
		return nil
	}
ELEM:
	for _, el := range elements {
		v1 := el.String()
		for i, el2 := range *l {
			if el2.String() == v1 {
				// delete found element
				*l = append((*l)[:i], (*l)[i+1:]...)
				continue ELEM
			}
		}
		return fmt.Errorf("Can't find element '%s'", v1)
	}
	return nil
}

func getNamedUnion(name string, val interface{}) (*ast.NamedUnion, error) {
	l, err := getElementList(val)
	if err != nil {
		return nil, err
	}
	return &ast.NamedUnion{Name: name, Elements: l}, nil
}

func getElementList(val interface{}) ([]ast.Element, error) {
	var elements []ast.Element
	addOneElement := func(val string) error {
		l, err := parser.ParseUnion([]byte(val))
		if err != nil {
			return err
		}
		if len(l) != 1 {
			return fmt.Errorf("Expecting exactly on element in string")
		}
		elements = append(elements, l...)
		return nil
	}
	switch x := val.(type) {
	case nil:
		return nil, fmt.Errorf("Missing value for element")
	case string:
		err := addOneElement(x)
		if err != nil {
			return nil, err
		}
	case []interface{}:
		for _, v := range x {
			if s, ok := v.(string); ok {
				err := addOneElement(s)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("Unexpected type in JSON array: %T", v)
			}
		}
	default:
		return nil, fmt.Errorf("Unexpected type in element list: %T", val)
	}
	return elements, nil
}

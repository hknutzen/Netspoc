package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
)

type change struct {
	method     string
	okIfExists bool
	val        json.RawMessage
}

func (s *state) patch(j *job) error {
	var p struct {
		Path       string
		Value      json.RawMessage
		OkIfExists bool `json:"ok_if_exists"`
	}
	getParams(j, &p)
	c := change{val: p.Value, okIfExists: p.OkIfExists}
	switch j.Method {
	case "delete", "add", "replace":
		c.method = j.Method
	default:
		return fmt.Errorf("Invalid method '%s'", j.Method)
	}
	if len(p.Path) == 0 {
		return fmt.Errorf("Invalid empty path")
	}
	names := strings.Split(p.Path, ",")
	// Find toplevel node
	topName := names[0]
	var top ast.Toplevel
	s.Modify(func(toplevel ast.Toplevel) bool {
		if toplevel.GetName() == topName {
			top = toplevel
		}
		return false
	})
	names = names[1:]
	if top == nil {
		if len(names) == 0 {
			return s.addToplevel(topName, c)
		}
		return fmt.Errorf("Can't modify unknown toplevel object %s", topName)
	}
	process := func() error {
		if len(names) == 0 {
			return s.patchToplevel(top, c)
		}
		name := names[0]
		var ts *ast.TopStruct
		switch x := top.(type) {
		case *ast.TopList:
			return patchElemList(&x.Elements, names, c)
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
		return patchAttributes(&ts.Attributes, names, c)
	}
	err := process()
	if err == nil {
		top.Order()
		// Mark object as modified.
		s.ModifyObj(topName, func(toplevel ast.Toplevel) error { return nil })
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
			return fmt.Errorf("rule count %d doesn't match, have %d rules",
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
		return fmt.Errorf("Must not delete '%s' from rule", name)
	}
	switch name {
	case "src":
		return patchElemList(&rule.Src.Elements, names[1:], c)
	case "dst":
		return patchElemList(&rule.Dst.Elements, names[1:], c)
	case "prt":
		return patchAttributes(&[]*ast.Attribute{rule.Prt}, names, c)
	case "log":
		return patchAttributes(&[]*ast.Attribute{rule.Log}, names, c)
	}
	return fmt.Errorf("Rule has no attribute '%s'", name)
}

func newRule(l *[]*ast.Rule, c change) error {
	if c.method != "add" {
		return fmt.Errorf("Rule number must be given for '%s'", c.method)
	}
	v, err := decode(c.val)
	if err != nil {
		return err
	}
	def, err := getRuleDef(v)
	if err != nil {
		return err
	}
	rule, err := parser.ParseRule([]byte(def))
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

func patchAttributes(l *[]*ast.Attribute, names []string, c change) error {
	name := names[0]
	names = names[1:]
	for i, a := range *l {
		if a.Name == name {
			if len(names) != 0 {
				if len(a.ComplexValue) == 0 {
					return fmt.Errorf("Can't descend into %s", a.Name)
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
			return fmt.Errorf("Missing value to %s at %s", c.method, a.Name)
		}
	}
	return newAttribute(l, name, c)
}

func newAttribute(l *[]*ast.Attribute, name string, c change) error {
	if c.method != "add" {
		return fmt.Errorf("Can't find attribute '%s'", name)
	}
	a := &ast.Attribute{Name: name}
	if err := setAttrValue(a, c); err != nil {
		return err
	}
	*l = append(*l, a)
	return nil
}

func patchElemList(l *[]ast.Element, names []string, c change) error {
	v, err := decode(c.val)
	if err != nil {
		return err
	}
	val := ""
	switch x := v.(type) {
	case nil:
		return fmt.Errorf("Missing value to change in elements")
	case string:
		val = x
	case []interface{}:
		for _, v := range x {
			if val != "" {
				val += ","
			}
			if s, ok := v.(string); ok {
				val += s
			} else {
				return fmt.Errorf("Unexpected type in JSON array: %T", v)
			}
		}
	}
	if len(names) != 0 {
		return fmt.Errorf("Can't descend into value '%s'", val)
	}
	elements, err := parser.ParseUnion([]byte(val))
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
		return fmt.Errorf("Can't find element '%s'", val)
	}
	return nil
}

func (s *state) addToplevel(name string, c change) error {
	if c.method != "add" {
		return fmt.Errorf("Can't %s unknown toplevel node '%s'", c.method, name)
	}
	a, err := s.getToplevelDef(name, c)
	if err != nil {
		return err
	}
	s.AddTopLevel(a)
	return nil
}

func (s *state) getToplevelDef(name string, c change) (ast.Toplevel, error) {
	var definition string
	var err error
	v, err := decode(c.val)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(name, "service:") {
		definition, err = getServiceDef(name, v)
	} else {
		definition, err = getAttrDef(name, v)
	}
	if err != nil {
		return nil, err
	}
	a, err := parser.ParseToplevel([]byte(definition))
	if err != nil {
		return nil, err
	}
	a.Order()
	return a, nil
}

func (s *state) patchToplevel(n ast.Toplevel, c change) error {
	if c.method == "delete" && c.val == nil {
		return s.DeleteToplevel(n.GetName())
	}
	if x, ok := n.(*ast.TopList); ok {
		err := patchElemList(&x.Elements, nil, c)
		x.Order()
		return err
	}
	if c.method == "replace" {
		a, err := s.getToplevelDef(n.GetName(), c)
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
	return fmt.Errorf("Can't redefine '%s'", n.GetName())
}

func getServiceDef(name string, v interface{}) (string, error) {
	switch x := v.(type) {
	default:
		return "", fmt.Errorf(
			"Expecting JSON object in definition of %s but got: %T", name, v)
	case string:
		return name + "=" + x, nil
	case map[string]interface{}:
		user, found := x["user"]
		if !found {
			return "", fmt.Errorf("Missing key 'user' in '%s'", name)
		}
		delete(x, "user")
		rules, found := x["rules"]
		if !found {
			return "", fmt.Errorf("Missing key 'rules' in '%s'", name)
		}
		delete(x, "rules")
		l, ok := rules.([]interface{})
		if !ok {
			return "", fmt.Errorf(
				"Expecting JSON array after 'rules' but got: %T", rules)
		}
		serviceDef, err := getAttrDef(name, x)
		if err != nil {
			return "", err
		}
		userDef, err := getAttrDef("user", user)
		if err != nil {
			return "", err
		}
		rulesDef := ""
		for _, v := range l {
			rule, err := getRuleDef(v)
			if err != nil {
				return "", err
			}
			rulesDef += rule
		}
		return serviceDef[:len(serviceDef)-1] + userDef + rulesDef + "}", nil
	}
}

func getRuleDef(v interface{}) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	buf := ""
	obj, ok := v.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Unexpected type when reading rule: %T", v)
	}
	for _, key := range []string{"action", "src", "dst", "prt"} {
		val, found := obj[key]
		if !found {
			return "", fmt.Errorf(
				"Missing key %s in JSON object of rule", key)
		}
		delete(obj, key)
		attr, err := getAttrDef(key, val)
		if err != nil {
			return "", err
		}
		switch key {
		case "action":
			switch attr {
			case "action=permit;":
				buf += "permit "
			case "action=deny;":
				buf += "deny "
			default:
				return "", fmt.Errorf("Expected 'permit' or 'deny' in '%s'", attr)
			}
		default:
			buf += attr
		}
	}
	for key, val := range obj {
		attr, err := getAttrDef(key, val)
		if err != nil {
			return "", err
		}
		buf += attr
	}
	return buf, nil
}

func getAttrDef(name string, v interface{}) (string, error) {
	if name == "description" {
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("Expecting string after description")
		}
		return name + "=" + s + "\n", nil
	}
	buf := name
TYPE:
	switch x := v.(type) {
	case nil:
		buf += ";"
	case string:
		x = strings.TrimSpace(x)
		buf += "=" + x
		if len(x) > 0 {
			switch x[len(x)-1] {
			case ';', '}':
				break TYPE
			}
		}
		buf += ";"
	case []interface{}:
		buf += "="
		for _, v := range x {
			s, ok := v.(string)
			if !ok {
				return "", fmt.Errorf("Unexpected type in JSON array: %T", v)
			}
			buf += s + ","
		}
		buf += ";"
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf += "={"
		for _, k := range keys {
			attr, err := getAttrDef(k, x[k])
			if err != nil {
				return "", err
			}
			buf += attr
		}
		buf += "}"
	default:
		return "", fmt.Errorf("Unexpected type in JSON value: %T", v)
	}
	return buf, nil
}

func setAttrValue(a *ast.Attribute, c change) error {
	v, err := decode(c.val)
	if err != nil {
		return err
	}
	def, err := getAttrDef(a.Name, v)
	if err != nil {
		return err
	}
	a2, err := parser.ParseAttribute([]byte(def))
	if err != nil {
		return err
	}
	a.ValueList = a2.ValueList
	a.ComplexValue = a2.ComplexValue
	return nil
}

func patchValue(a *ast.Attribute, names []string, c change) error {
	if c.method == "replace" ||
		c.method == "add" && len(a.ComplexValue) == 0 && len(a.ValueList) == 0 {

		return setAttrValue(a, c)
	}
	if a.ComplexValue != nil {
		if c.method == "add" {
			return fmt.Errorf("Can't add to complex value of '%s'", a.Name)
		}
		return fmt.Errorf("Can't delete from complex value of '%s'", a.Name)
	}
	a2 := &ast.Attribute{Name: a.Name}
	if err := setAttrValue(a2, c); err != nil {
		return err
	}
	if a2.ComplexValue != nil {
		return fmt.Errorf("Can't %s complex value to value list of '%s'",
			c.method, a.Name)
	}
	if c.method == "add" {
		a.ValueList = append(a.ValueList, a2.ValueList...)
		return nil
	}
VAL:
	for _, v2 := range a2.ValueList {
		val := v2.Value
		for i, v := range a.ValueList {
			if v.Value == val {
				// delete found element
				a.ValueList = append(a.ValueList[:i], a.ValueList[i+1:]...)
				continue VAL
			}
		}
		return fmt.Errorf("Can't find value '%s'", val)
	}
	return nil
}

func decode(val json.RawMessage) (interface{}, error) {
	var v interface{}
	if err := json.Unmarshal(val, &v); err != nil {
		return nil, err
	}
	return v, nil
}

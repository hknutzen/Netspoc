// Package parser implements a parser for source files of Netspoc
// policy language.  The output is an abstract syntax
// tree (AST) representing the Netspoc source.
//
package parser

import (
	"github.com/hknutzen/spoc-parser/ast"
	"github.com/hknutzen/spoc-parser/scanner"
	"net"
	"strconv"
	"strings"
)

// The parser structure holds the parser's internal state.
type parser struct {
	scanner  scanner.Scanner
	fileName string

	// Next token
	pos int    // token position
	tok string // token literal, one token look-ahead
}

func (p *parser) init(src []byte, fname string) {
	p.scanner.Init(src, fname)
	p.fileName = fname

	p.next()
}

// ----------------------------------------------------------------------------
// Parsing support

// Advance to the next token.
func (p *parser) next() {
	p.pos, p.tok = p.scanner.Token()
}

// Advance to the next token, but take "-" and ":" as separator.
func (p *parser) nextPort() {
	p.pos, p.tok = p.scanner.SimpleToken()
}

// Advance to the next token, but token contains any character except
// ';', '#', '\n'. A single ";" may be returned.
func (p *parser) nextSingle() {
	p.pos, p.tok = p.scanner.TokenToSemicolon()
}

// Advance to the next token, but token contains any character except
// ',', ';', '#', '\n'. A single "," or ";" may be returned.
func (p *parser) nextMulti() {
	p.pos, p.tok = p.scanner.TokenToComma()
}

func (p *parser) syntaxErr(format string, args ...interface{}) {
	p.scanner.SyntaxErr(format, args...)
}

func (p *parser) expect(tok string) int {
	pos := p.pos
	if p.tok != tok {
		p.syntaxErr("Expected '%s'", tok)
	}
	p.next() // make progress
	return pos
}

func (p *parser) expectSpecial(tok string, getNext func(*parser)) {
	if p.tok != tok {
		p.syntaxErr("Expected '%s'", tok)
	}
	getNext(p)
}

func (p *parser) expectLeave(tok string) {
	if p.tok != tok {
		p.syntaxErr("Expected '%s'", tok)
	}
}

func (p *parser) check(tok string) bool {
	if p.tok != tok {
		return false
	}
	p.next()
	return true
}

func (p *parser) checkPos(tok string) int {
	if p.tok != tok {
		return -1
	}
	end := p.pos + len(tok)
	p.next()
	return end
}

func isSimpleName(n string) bool {
	return n != "" && strings.IndexAny(n, ".:/@") == -1
}

func isDomain(n string) bool {
	for _, part := range strings.Split(n, ".") {
		if !isSimpleName(part) {
			return false
		}
	}
	return n != ""
}

func (p *parser) verifyHostname(name string) {
	err := false
	if strings.HasPrefix(name, "id:") {
		id := name[3:]
		i := strings.Index(id, "@")
		// Leading "@" is ok.
		err = i > 0 && !isDomain(id[:i]) || !isDomain(id[i+1:])
	} else {
		err = !isSimpleName(name)
	}
	if err {
		p.syntaxErr("Hostname expected")
	}
}

func isNetworkName(n string) bool {
	i := strings.Index(n, "/")
	return (i == -1 || isSimpleName(n[:i])) && isSimpleName(n[i+1:])
}

func (p *parser) verifyNetworkName(n string) {
	if !isNetworkName(n) {
		p.syntaxErr("Name or bridged name expected")
	}
}

func (p *parser) verifySimpleName(n string) {
	if !isSimpleName(n) {
		p.syntaxErr("Name expected")
	}
}

func isRouterName(n string) bool {
	i := strings.Index(n, "@")
	return (i == -1 || isSimpleName(n[:i])) && isSimpleName(n[i+1:])
}

func (p *parser) user() *ast.User {
	a := new(ast.User)
	a.Start = p.pos
	p.next()
	return a
}

func (p *parser) namedRef(typ, name string) ast.Element {
	a := new(ast.NamedRef)
	a.Start = p.pos
	a.Typ = typ
	a.Name = name
	p.next()
	return a
}

func (p *parser) hostRef(typ, name string) ast.Element {
	p.verifyHostname(name)
	return p.namedRef(typ, name)
}

func (p *parser) networkRef(typ, name string) ast.Element {
	p.verifyNetworkName(name)
	return p.namedRef(typ, name)
}

func (p *parser) simpleRef(typ, name string) ast.Element {
	p.verifySimpleName(name)
	return p.namedRef(typ, name)
}

func (p *parser) selector() (string, int) {
	result := p.tok
	if !(result == "auto" || result == "all") {
		p.syntaxErr("Expected [auto|all]")
	}
	p.next()
	pos := p.expect("]")
	return result, pos + 1
}

func (p *parser) intfRef(typ, name string) ast.Element {
	start := p.pos
	a := new(ast.IntfRef)
	a.Start = start
	a.Typ = typ
	i := strings.Index(name, ".")
	if i == -1 {
		p.syntaxErr("Interface name expected")
	}
	router := name[:i]
	net := name[i+1:]
	err := !isRouterName(router)
	p.next()
	var ext string
	var end int
	if net == "[" {
		ext, end = p.selector()
	} else {
		i := strings.Index(net, ".")
		if i != -1 {
			ext = net[i+1:]
			err = err || !isSimpleName(ext)
			net = net[:i]
		}
		err = err || !isNetworkName(net)
		end = start + len(name)
	}
	if err {
		p.syntaxErr("Interface name expected")
	}
	a.Router = router
	a.Network = net   // If Network is "[",
	a.Extension = ext // then Extension contains selector.
	a.Next = end
	return a
}

func (p *parser) simpleAuto(start int, typ string) ast.Element {
	a := new(ast.SimpleAuto)
	a.Start = start
	a.Typ = typ
	a.Elements, a.Next = p.union("]")
	return a
}

func (p *parser) ipPrefix() *net.IPNet {
	if i := strings.Index(p.tok, "/"); i != -1 {
		if ip := net.ParseIP(p.tok[:i]); ip != nil {
			if len, err := strconv.Atoi(p.tok[i+1:]); err == nil {
				bits := 8
				if ip4 := ip.To4(); ip4 != nil {
					bits *= net.IPv4len
				} else {
					bits *= net.IPv6len
				}
				if mask := net.CIDRMask(len, bits); mask != nil {
					p.next()
					return &net.IPNet{IP: ip, Mask: mask}
				}
			}
			p.syntaxErr("Prefixlen expected")
		} else {
			p.syntaxErr("IP address expected")
		}
	}
	p.syntaxErr("Expected 'IP/prefixlen'")
	return nil
}

func (p *parser) aggAuto(start int, typ string) ast.Element {
	a := new(ast.AggAuto)
	a.Start = start
	a.Typ = typ
	if p.check("ip") {
		p.check("=")
		a.Net = p.ipPrefix()
		p.expect("&")
	}
	a.Elements, a.Next = p.union("]")
	return a
}

func (p *parser) intfAuto(start int, typ string) ast.Element {
	a := new(ast.IntfAuto)
	a.Start = start
	a.Typ = typ
	if p.check("managed") {
		a.Managed = true
		p.expect("&")
	}
	a.Elements, _ = p.union("]")
	p.expect(".[")
	a.Selector, a.Next = p.selector()
	return a
}

func (p *parser) checkTypedName() (string, string) {
	tok := p.tok
	i := strings.Index(tok, ":")
	if i == -1 {
		return "", ""
	}
	typ := tok[:i]
	name := tok[i+1:]
	p.next()
	return typ, name
}

func (p *parser) typedName() (string, string) {
	tok := p.tok
	i := strings.Index(tok, ":")
	if i == -1 {
		p.syntaxErr("Typed name expected")
	}
	typ := tok[:i]
	name := tok[i+1:]
	return typ, name
}

var elementType = map[string]func(*parser, string, string) ast.Element{
	"host":      (*parser).hostRef,
	"network":   (*parser).networkRef,
	"interface": (*parser).intfRef,
	"any":       (*parser).simpleRef,
	"area":      (*parser).simpleRef,
	"group":     (*parser).simpleRef,
}

var autoGroupType map[string]func(*parser, int, string) ast.Element

func init() {
	autoGroupType = map[string]func(*parser, int, string) ast.Element{
		"host":      (*parser).simpleAuto,
		"network":   (*parser).simpleAuto,
		"interface": (*parser).intfAuto,
		"any":       (*parser).aggAuto,
	}
}

func (p *parser) extendedName() ast.Element {
	if p.tok == "user" {
		return p.user()
	}
	typ, name := p.typedName()
	if name == "[" {
		start := p.pos
		m, found := autoGroupType[typ]
		if !found {
			p.syntaxErr("Unexpected automatic group")
		}
		p.next()
		return m(p, start, typ)
	}
	m, found := elementType[typ]
	if !found {
		p.syntaxErr("Unknown element type")
	}
	return m(p, typ, name)
}

func (p *parser) complement() ast.Element {
	start := p.pos
	if p.check("!") {
		a := new(ast.Complement)
		a.Start = start
		a.Element = p.extendedName()
		return a
	} else {
		return p.extendedName()
	}
}

func (p *parser) intersection() ast.Element {
	var intersection []ast.Element
	start := p.pos
	intersection = append(intersection, p.complement())
	for p.check("&") {
		intersection = append(intersection, p.complement())
	}
	if len(intersection) > 1 {
		a := new(ast.Intersection)
		a.Start = start
		a.Elements = intersection
		return a
	} else {
		return intersection[0]
	}
}

// Read comma separated list of objects stopped by stopToken.
// Read at least one element.
// Return list of ASTs of read elements
// and position after stopToken.
func (p *parser) union(stopToken string) ([]ast.Element, int) {
	var union []ast.Element
	var end int
	for {
		union = append(union, p.intersection())
		if end = p.checkPos(stopToken); end >= 0 {
			break
		}
		p.expect(",")

		// Allow trailing comma.
		if end = p.checkPos(stopToken); end >= 0 {
			break
		}
	}
	return union, end
}

func (p *parser) description() *ast.Description {
	start := p.pos
	if p.check("description") {
		if p.tok != "=" {
			p.syntaxErr("Expected '='")
		}
		p.pos, p.tok = p.scanner.ToEOLorComment()
		text := p.tok
		end := p.pos + len(text)
		p.next()
		a := new(ast.Description)
		a.Start = start
		a.Text = text
		a.Next = end
		return a
	}
	return nil
}

func (p *parser) name() string {
	result := p.tok
	p.next()
	return result
}

func (p *parser) value(nextSpecial func(*parser)) *ast.Value {
	a := new(ast.Value)
	a.Start = p.pos
	a.Value = p.tok
	nextSpecial(p)
	return a
}

func (p *parser) addMulti(a *ast.Value, nextSpecial func(*parser)) {
	for !(p.tok == "," || p.tok == ";") {
		a.Value += " " + p.tok
		nextSpecial(p)
	}
}

func (p *parser) multiValue(nextSpecial func(*parser)) *ast.Value {
	a := p.value(nextSpecial)
	p.addMulti(a, nextSpecial)
	return a
}

func (p *parser) protocol(nextSpecial func(*parser)) *ast.Value {
	nextSpecial = (*parser).nextPort
	a := p.value(nextSpecial)
	if strings.Index(a.Value, ":") == -1 {
		p.addMulti(a, nextSpecial)
	}
	return a
}

func (p *parser) valueList(
	getValue func(*parser, func(*parser)) *ast.Value,
	nextSpecial func(*parser)) ([]*ast.Value, int) {

	var list []*ast.Value
	var end int
	for {
		list = append(list, getValue(p, nextSpecial))
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		p.expectSpecial(",", nextSpecial)

		// Allow trailing comma.
		if end = p.checkPos(";"); end >= 0 {
			break
		}
	}
	return list, end
}

func (p *parser) complexValue(
	nextSpecial func(*parser)) ([]*ast.Attribute, int) {
	var list []*ast.Attribute
	var end int
	for {
		if end = p.checkPos("}"); end >= 0 {
			break
		}
		list = append(list, p.specialAttribute(nextSpecial))
	}
	return list, end
}

var specialTokenAttr = map[string]func(*parser){
	"ldap_id":     (*parser).nextSingle,
	"ldap_append": (*parser).nextSingle,
	"admins":      (*parser).nextMulti,
	"watchers":    (*parser).nextMulti,
	"range":       (*parser).nextPort,
}

var specialSubTokenAttr = map[string]func(*parser){
	"radius_attributes": (*parser).nextSingle,
}

var specialValueAttr = map[string]func(*parser, func(*parser)) *ast.Value{
	"prt":            (*parser).protocol,
	"general_permit": (*parser).protocol,
	"lifetime":       (*parser).multiValue,
	"range":          (*parser).multiValue,
}

func (p *parser) specialAttribute(nextSpecial func(*parser)) *ast.Attribute {
	a := new(ast.Attribute)
	a.Start = p.pos
	a.Name = p.name()
	if end := p.checkPos(";"); end >= 0 {
		a.Next = end
		return a
	}
	if n := specialTokenAttr[a.Name]; n != nil {
		nextSpecial = n
	}
	p.expectSpecial("=", nextSpecial)
	if p.check("{") {
		if n := specialSubTokenAttr[a.Name]; n != nil {
			nextSpecial = n
		}
		a.ComplexValue, a.Next = p.complexValue(nextSpecial)
	} else {
		getValue := specialValueAttr[a.Name]
		if getValue == nil {
			getValue = (*parser).value
		}
		a.ValueList, a.Next = p.valueList(getValue, nextSpecial)
	}
	return a
}

func (p *parser) attribute() *ast.Attribute {
	return p.specialAttribute((*parser).next)
}

func (p *parser) topListHead() ast.TopBase {
	var a ast.TopBase
	a.Start = p.pos
	a.Name = p.tok
	p.next()
	p.expect("=")
	a.Description = p.description()
	return a
}

func (p *parser) topList() ast.Toplevel {
	a := new(ast.TopList)
	a.TopBase = p.topListHead()
	if a.Next = p.checkPos(";"); a.Next < 0 {
		a.Elements, a.Next = p.union(";")
	}
	return a
}

func (p *parser) protocolgroup() ast.Toplevel {
	a := new(ast.Protocolgroup)
	a.TopBase = p.topListHead()
	if a.Next = p.checkPos(";"); a.Next < 0 {
		a.ValueList, a.Next = p.valueList((*parser).protocol, (*parser).next)
	}
	return a
}

func (p *parser) namedUnion() *ast.NamedUnion {
	a := new(ast.NamedUnion)
	a.Start = p.pos
	a.Name = p.name()
	p.expect("=")
	a.Elements, a.Next = p.union(";")
	return a
}

func (p *parser) rule() *ast.Rule {
	a := new(ast.Rule)
	a.Start = p.pos
	switch p.tok {
	case "deny":
		a.Deny = true
		fallthrough
	case "permit":
		p.next()
		p.expectLeave("src")
		a.Src = p.namedUnion()
		p.expectLeave("dst")
		a.Dst = p.namedUnion()
		p.expectLeave("prt")
		a.Prt = p.attribute()
		a.Next = a.Prt.Next
		if p.tok == "log" {
			a.Log = p.attribute()
			a.Next = a.Log.Next
		}
	default:
		p.syntaxErr("Expected 'permit' or 'deny'")
	}
	return a
}

func (p *parser) topStructHead() ast.TopStruct {
	var a ast.TopStruct
	a.Start = p.pos
	a.Name = p.tok
	p.next()
	p.expect("=")
	p.expect("{")
	a.Description = p.description()
	return a
}

func (p *parser) attributes() ([]*ast.Attribute, int) {
	result := make([]*ast.Attribute, 0)
	var end int
	for {
		if p.tok == "}" {
			end = p.pos
			p.next()
			break
		}
		result = append(result, p.attribute())
	}
	return result, end
}

func (p *parser) service() ast.Toplevel {
	a := new(ast.Service)
	a.TopStruct = p.topStructHead()
	for {
		if p.tok == "user" {
			break
		}
		a.Attributes = append(a.Attributes, p.attribute())
	}
	u := new(ast.NamedUnion)
	u.Start = p.pos
	p.expectLeave("user")
	u.Name = p.name()
	p.expect("=")
	if p.check("foreach") {
		a.Foreach = true
	}
	u.Elements, u.Next = p.union(";")
	a.User = u
	for {
		if p.tok == "}" {
			a.Next = p.pos
			p.next()
			break
		}
		a.Rules = append(a.Rules, p.rule())
	}
	return a
}

func (p *parser) topStruct() ast.Toplevel {
	a := p.topStructHead()
	a.Attributes, a.Next = p.attributes()
	return &a
}

var globalType = map[string]func(*parser) ast.Toplevel{
	"network":         (*parser).topStruct,
	"router":          (*parser).topStruct,
	"any":             (*parser).topStruct,
	"area":            (*parser).topStruct,
	"group":           (*parser).topList,
	"protocol":        (*parser).topList,
	"protocolgroup":   (*parser).protocolgroup,
	"pathrestriction": (*parser).topList,
	"service":         (*parser).service,
	"owner":           (*parser).topStruct,
	"crypto":          (*parser).topStruct,
	"ipsec":           (*parser).topStruct,
	"isakmp":          (*parser).topStruct,
}

func (p *parser) toplevel() ast.Toplevel {
	typ, name := p.typedName()

	// Check for xxx:xxx | router:xx@xx | network:xx/xx
	if !(typ == "router" && isRouterName(name) ||
		typ == "network" && isNetworkName(name) || isSimpleName(name)) {
		p.syntaxErr("Invalid token")
	}
	m, found := globalType[typ]
	if !found {
		p.syntaxErr("Unknown global definition")
	}
	ast := m(p)
	ast.SetFileName(p.fileName)
	return ast
}

// ----------------------------------------------------------------------------
// Source files

func (p *parser) file() []ast.Toplevel {
	var list []ast.Toplevel
	for p.tok != "" {
		list = append(list, p.toplevel())
	}

	return list
}

func ParseFile(src []byte, fileName string) []ast.Toplevel {
	p := new(parser)
	p.init(src, fileName)
	return p.file()
}

// Package parser implements a parser for source files of Netspoc
// policy language.  The output is an abstract syntax
// tree (AST) representing the Netspoc source.
//
package parser

import (
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/scanner"
	"net"
	"strconv"
	"strings"
)

// The parser structure holds the parser's internal state.
type parser struct {
	scanner  scanner.Scanner
	fileName string

	// Next token
	pos   int    // token position
	isSep bool   // token is single separator character
	tok   string // token literal, one token look-ahead
}

func (p *parser) init(src []byte, fname string) {
	ah := func(e error) { p.abort(e) }

	p.scanner.Init(src, fname, ah)
	p.fileName = fname

	p.next()
}

// ----------------------------------------------------------------------------
// Parsing support

// Advance to the next token.
func (p *parser) next() {
	p.pos, p.isSep, p.tok = p.scanner.Token()
}

// Advance to the next token, but take "-", "/" and ":" as separator.
func (p *parser) nextProto() {
	p.pos, p.isSep, p.tok = p.scanner.ProtoToken()
}

// Advance to the next token, but take "-" as separator.
func (p *parser) nextIPRange() {
	p.pos, p.isSep, p.tok = p.scanner.IPRangeToken()
}

// Advance to the next token, but token contains any character except
// ';', '#', '\n'. A single ";" may be returned.
func (p *parser) nextSingle() {
	p.pos, p.isSep, p.tok = p.scanner.TokenToSemicolon()
}

// Advance to the next token, but token contains any character except
// ',', ';', '#', '\n'. A single "," or ";" may be returned.
func (p *parser) nextMulti() {
	p.pos, p.isSep, p.tok = p.scanner.TokenToComma()
}

func (p *parser) syntaxErr(format string, args ...interface{}) {
	p.scanner.SyntaxErr(p.pos, format, args...)
}

func (p *parser) expect(tok string) int {
	pos := p.pos
	if p.tok != tok {
		p.syntaxErr("Expected '%s'", tok)
	}
	p.next() // make progress
	return pos + len(tok)
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

func (p *parser) checkSpecial(tok string, getNext func(*parser)) bool {
	if p.tok != tok {
		return false
	}
	getNext(p)
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

func (p *parser) getNonSep() string {
	if p.isSep {
		if p.tok == "" {
			// At EOF
			p.syntaxErr("Expected something")
		} else {
			p.syntaxErr("Unexpected separator '%s'", p.tok)
		}
	}
	return p.tok
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
	a.Type = typ
	a.Name = name
	p.next()
	return a
}

func (p *parser) selector() (string, int) {
	result := p.tok
	if !(result == "auto" || result == "all") {
		p.syntaxErr("Expected [auto|all]")
	}
	p.next()
	pos := p.expect("]")
	return result, pos
}

func (p *parser) intfRef(typ, name string) ast.Element {
	start := p.pos
	a := new(ast.IntfRef)
	a.Start = start
	a.Type = typ
	i := strings.Index(name, ".")
	if i == -1 {
		p.syntaxErr("Interface name expected")
	}
	router := name[:i]
	net := name[i+1:]
	p.next()
	var ext string
	var end int
	if net == "[" {
		ext, end = p.selector()
	} else {
		i := strings.Index(net, ".")
		if i != -1 {
			ext = net[i+1:]
			net = net[:i]
		}
		end = start + len(typ) + 1 + len(name)
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
	a.Type = typ
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
	a.Type = typ
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
	a.Type = typ
	if p.check("managed") {
		a.Managed = true
		p.expect("&")
	}
	a.Elements, _ = p.union("]")
	p.expect(".[")
	a.Selector, a.Next = p.selector()
	return a
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
	"host":      (*parser).namedRef,
	"network":   (*parser).namedRef,
	"interface": (*parser).intfRef,
	"any":       (*parser).namedRef,
	"area":      (*parser).namedRef,
	"group":     (*parser).namedRef,
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
// Return list of ASTs of read elements
// and position after stopToken.
func (p *parser) union(stopToken string) ([]ast.Element, int) {
	var union []ast.Element
	var end int
	for {
		if end = p.checkPos(stopToken); end >= 0 {
			break
		}
		union = append(union, p.intersection())
		if !p.check(",") {
			// Allow trailing comma.
			end = p.expect(stopToken)
			break
		}
	}
	return union, end
}

func (p *parser) description() *ast.Description {
	start := p.pos
	if p.check("description") {
		p.expectLeave("=")
		p.pos, p.tok = p.scanner.ToEOLorComment()
		// Prevent two spaces before comment when printing.
		text := strings.TrimRight(p.tok, " ")
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
	result := p.getNonSep()
	p.next()
	return result
}

func (p *parser) value(nextSpecial func(*parser)) *ast.Value {
	a := new(ast.Value)
	a.Start = p.pos
	a.Value = p.getNonSep()
	nextSpecial(p)
	return a
}

func (p *parser) addMulti(a *ast.Value, nextSpecial func(*parser)) {
	for !(p.tok == "," || p.tok == ";" || p.tok == "") {
		a.Value += " " + p.tok
		nextSpecial(p)
	}
}

func (p *parser) multiValue(nextSpecial func(*parser)) *ast.Value {
	a := p.value(nextSpecial)
	p.addMulti(a, nextSpecial)
	return a
}

func (p *parser) protocolRef(nextSpecial func(*parser)) *ast.Value {
	return p.multiValue((*parser).nextProto)
}

func (p *parser) valueList(
	getValue func(*parser, func(*parser)) *ast.Value,
	nextSpecial func(*parser)) ([]*ast.Value, int) {

	var list []*ast.Value
	var end int
	for {
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		list = append(list, getValue(p, nextSpecial))
		if !p.checkSpecial(",", nextSpecial) {
			// Allow trailing comma.
			end = p.expect(";")
			break
		}
	}
	return list, end
}

func (p *parser) complexValue(
	nextSpecial func(*parser)) ([]*ast.Attribute, int) {
	list := make([]*ast.Attribute, 0)
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
	"range":       (*parser).nextIPRange,
}

var specialSubTokenAttr = map[string]func(*parser){
	"radius_attributes": (*parser).nextSingle,
}

var specialValueAttr = map[string]func(*parser, func(*parser)) *ast.Value{
	"prt":            (*parser).protocolRef,
	"general_permit": (*parser).protocolRef,
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

func (p *parser) attributeNoToplevel() *ast.Attribute {
	if i := strings.Index(p.tok, ":"); i != -1 {
		typ := p.tok[:i]
		if _, found := globalType[typ]; found {
			p.syntaxErr("Expected '}'")
		}
	}
	return p.attribute()
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
	a.Elements, a.Next = p.union(";")
	return a
}

func (p *parser) protocolgroup() ast.Toplevel {
	a := new(ast.Protocolgroup)
	a.TopBase = p.topListHead()
	a.ValueList, a.Next = p.valueList((*parser).protocolRef, (*parser).next)
	return a
}

func (p *parser) protocol() ast.Toplevel {
	a := new(ast.Protocol)
	a.TopBase = p.topListHead()
	for p.tok != ";" && p.tok != "" {
		if a.Value != "" && p.tok != "," {
			a.Value += " "
		}
		a.Value += p.tok
		p.nextProto()
	}
	a.Next = p.expect(";")
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
			a.Next = p.pos + 1
			p.next()
			break
		}
		a.Rules = append(a.Rules, p.rule())
	}
	return a
}

func (p *parser) network() ast.Toplevel {
	a := new(ast.Network)
	a.TopStruct = p.topStructHead()
	for {
		if p.tok == "}" {
			a.Next = p.pos + 1
			p.next()
			break
		} else if strings.HasPrefix(p.tok, "host:") {
			a.Hosts = append(a.Hosts, p.attribute())
		} else {
			a.Attributes = append(a.Attributes, p.attributeNoToplevel())
		}
	}
	return a
}

func (p *parser) router() ast.Toplevel {
	a := new(ast.Router)
	a.TopStruct = p.topStructHead()
	for {
		if p.tok == "}" {
			a.Next = p.pos + 1
			p.next()
			break
		} else if strings.HasPrefix(p.tok, "interface:") {
			a.Interfaces = append(a.Interfaces, p.attribute())
		} else {
			a.Attributes = append(a.Attributes, p.attributeNoToplevel())
		}
	}
	return a
}

func (p *parser) area() ast.Toplevel {
	a := new(ast.Area)
	a.TopStruct = p.topStructHead()
	for {
		if p.tok == "}" {
			a.Next = p.pos + 1
			p.next()
			break
		} else if p.tok == "border" {
			a.Border = p.namedUnion()
		} else if p.tok == "inclusive_border" {
			a.InclusiveBorder = p.namedUnion()
		} else {
			a.Attributes = append(a.Attributes, p.attributeNoToplevel())
		}
	}
	return a
}

func (p *parser) topStruct() ast.Toplevel {
	a := p.topStructHead()
	for {
		if p.tok == "}" {
			a.Next = p.pos + 1
			p.next()
			break
		}
		a.Attributes = append(a.Attributes, p.attributeNoToplevel())
	}
	return &a
}

var globalType map[string]func(*parser) ast.Toplevel

func init() {
	globalType = map[string]func(*parser) ast.Toplevel{
		"network":         (*parser).network,
		"router":          (*parser).router,
		"any":             (*parser).topStruct,
		"area":            (*parser).area,
		"group":           (*parser).topList,
		"protocol":        (*parser).protocol,
		"protocolgroup":   (*parser).protocolgroup,
		"pathrestriction": (*parser).topList,
		"service":         (*parser).service,
		"owner":           (*parser).topStruct,
		"crypto":          (*parser).topStruct,
		"ipsec":           (*parser).topStruct,
		"isakmp":          (*parser).topStruct,
	}
}

func (p *parser) toplevel() ast.Toplevel {
	typ, _ := p.typedName()
	m, found := globalType[typ]
	if !found {
		p.syntaxErr("Unknown global definition")
	}
	n := m(p)
	n.SetFileName(p.fileName)
	return n
}

// Read source files
func (p *parser) file() []ast.Toplevel {
	var list []ast.Toplevel
	for p.tok != "" {
		list = append(list, p.toplevel())
	}

	return list
}

// A bailout panic is raised to indicate early termination.
type bailout struct {
	err error
}

func (p *parser) abort(e error) {
	panic(bailout{err: e})
}

func ParseFile(src []byte, fileName string) (l []ast.Toplevel, err error) {
	p := new(parser)
	defer func() {
		if e := recover(); e != nil {
			if b, ok := e.(bailout); ok {
				err = b.err
			} else {
				// resume same panic if it's not a bailout
				panic(e)
			}
		}
	}()

	p.init(src, fileName)
	l = p.file()
	return
}

// Read from string
func ParseUnion(src []byte) (l []ast.Element, err error) {
	p := new(parser)
	defer func() {
		if e := recover(); e != nil {
			if b, ok := e.(bailout); ok {
				err = b.err
			} else {
				// resume same panic if it's not a bailout
				panic(e)
			}
		}
	}()

	src = append(src, ';')
	p.init(src, "command line")
	list, end := p.union(";")
	if end != len(src) {
		p.syntaxErr(`Unexpected content after ";"`)
	}
	l = list
	return
}

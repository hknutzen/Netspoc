// Package parser implements a parser for source files of Netspoc
// policy language.  The output is an abstract syntax
// tree (AST) representing the Netspoc source.
//
package parser

import (
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/scanner"
	"strings"
)

type Mode uint

const (
	ParseComments Mode = 1 << iota // parse comments and add them to AST
)

// The parser structure holds the parser's internal state.
type parser struct {
	scanner       scanner.Scanner
	fileName      string
	parseComments bool

	// Next token
	pos   int    // token position
	isSep bool   // token is single separator character
	tok   string // token literal, one token look-ahead
}

func (p *parser) init(src []byte, fname string, mode Mode) {
	ah := func(e error) { p.abort(e) }

	p.scanner.Init(src, fname, ah)
	p.fileName = fname
	p.parseComments = mode&ParseComments != 0

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

func (p *parser) readPreCmt(ign string) string {
	if !p.parseComments {
		return ""
	}
	return p.scanner.PreCmt(p.pos, ign)
}

func (p *parser) readPostCmtAfter(ign string) string {
	if !p.parseComments {
		return ""
	}
	return p.scanner.PostCmt(p.pos+len(p.tok), ign)
}

func (p *parser) setPostCmtAt(start int, a ast.Node) {
	if !p.parseComments {
		return
	}
	if c := p.scanner.PostCmt(start, ",;&!]"); c != "" {
		a.SetPostComment(c)
	}
}

func (p *parser) user() *ast.User {
	a := new(ast.User)
	p.next()
	return a
}

func (p *parser) namedRef(typ, name string) ast.Element {
	a := new(ast.NamedRef)
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
	a := new(ast.IntfRef)
	a.Type = typ
	r, net, found := strings.Cut(name, ".")
	if !found || r == "" || net == "" {
		p.syntaxErr("Interface name expected")
	}
	a.Router = r
	p.next()
	var ext string
	if net == "[" {
		var end int
		ext, end = p.selector()
		p.setPostCmtAt(end, a)
	} else {
		if p1, p2, found := strings.Cut(net, "."); found {
			net = p1
			ext = p2
		}
	}
	a.Network = net   // If Network is "[",
	a.Extension = ext // ...then Extension contains selector.
	return a
}

func (p *parser) simpleAuto(typ string) ast.Element {
	a := new(ast.SimpleAuto)
	a.Type = typ
	p.next()
	var end int
	a.Elements, end = p.union("]")
	p.setPostCmtAt(end, a)
	return a
}

func (p *parser) aggAuto(typ string) ast.Element {
	a := new(ast.AggAuto)
	a.Type = typ
	p.next()
	if p.check("ip") {
		p.check("=")
		a.Net = p.name()
		p.expect("&")
	}
	var end int
	a.Elements, end = p.union("]")
	p.setPostCmtAt(end, a)
	return a
}

func (p *parser) intfAuto(typ string) ast.Element {
	a := new(ast.IntfAuto)
	a.Type = typ
	p.next()
	if p.check("managed") {
		a.Managed = true
		p.expect("&")
	}
	a.Elements, _ = p.union("]")
	p.expect(".[")
	var end int
	a.Selector, end = p.selector()
	p.setPostCmtAt(end, a)
	return a
}

func (p *parser) typedName() (string, string) {
	tok := p.tok
	typ, name, found := strings.Cut(tok, ":")
	if !found || typ == "" || name == "" {
		p.syntaxErr("Typed name expected")
	}
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

var autoGroupType map[string]func(*parser, string) ast.Element

func init() {
	autoGroupType = map[string]func(*parser, string) ast.Element{
		"host":      (*parser).simpleAuto,
		"network":   (*parser).simpleAuto,
		"interface": (*parser).intfAuto,
		"any":       (*parser).aggAuto,
	}
}

func (p *parser) extendedName() ast.Element {
	preCmt := p.readPreCmt("&")
	postCmt := p.readPostCmtAfter(",;&!")
	var result ast.Element
	if p.tok == "user" {
		result = p.user()
	} else {
		typ, name := p.typedName()
		if name == "[" {
			m, found := autoGroupType[typ]
			if !found {
				p.syntaxErr("Unexpected automatic group")
			}
			result = m(p, typ)
		} else {
			m, found := elementType[typ]
			if !found {
				p.syntaxErr("Unknown element type")
			}
			result = m(p, typ, name)
		}
	}
	result.SetPreComment(preCmt)
	if result.PostComment() == "" {
		result.SetPostComment(postCmt)
	}
	return result
}

func (p *parser) complement() ast.Element {
	if p.check("!") {
		a := new(ast.Complement)
		c := p.readPreCmt("&!")
		el := p.extendedName()
		el.SetPreComment(c)
		a.Element = el
		return a
	} else {
		return p.extendedName()
	}
}

func (p *parser) intersection() ast.Element {
	intersection := []ast.Element{p.complement()}
	for p.check("&") {
		intersection = append(intersection, p.complement())
	}
	if len(intersection) > 1 {
		a := new(ast.Intersection)
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
	preCmt := p.readPreCmt("")
	if p.check("description") {
		p.expectLeave("=")
		p.pos, p.tok = p.scanner.ToEOLorComment()
		a := new(ast.Description)
		a.Text = p.tok
		a.SetPreComment(preCmt)
		a.SetPostComment(p.readPostCmtAfter(""))
		p.next()
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
	a.SetPreComment(p.readPreCmt(""))
	a.SetPostComment(p.readPostCmtAfter(",;}"))
	a.Value = p.getNonSep()
	nextSpecial(p)
	return a
}

func (p *parser) addMulti(a *ast.Value, nextSpecial func(*parser)) {
	for !(p.tok == "," || p.tok == ";" || p.tok == "") {
		a.Value += " " + p.tok
		nextSpecial(p)
	}
	a.SetPostComment(p.readPostCmtAfter(",;}"))
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
	nextSpecial func(*parser)) []*ast.Value {

	list := make([]*ast.Value, 0)
	for !p.check(";") {
		list = append(list, getValue(p, nextSpecial))
		if !p.checkSpecial(",", nextSpecial) {
			// Allow trailing comma.
			p.expect(";")
			break
		}
	}
	return list
}

func (p *parser) complexValue(nextSpecial func(*parser)) []*ast.Attribute {
	list := make([]*ast.Attribute, 0)
	for !p.check("}") {
		list = append(list, p.specialAttribute(nextSpecial))
	}
	return list
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
	a.SetPreComment(p.readPreCmt(""))
	a.SetPostComment(p.readPostCmtAfter(";={}"))
	a.Name = p.name()
	if p.check(";") {
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
		a.ComplexValue = p.complexValue(nextSpecial)
	} else {
		getValue := specialValueAttr[a.Name]
		if getValue == nil {
			getValue = (*parser).value
		}
		a.ValueList = p.valueList(getValue, nextSpecial)
	}
	return a
}

func (p *parser) attribute() *ast.Attribute {
	return p.specialAttribute((*parser).next)
}

func (p *parser) attributeNoToplevel() *ast.Attribute {
	if typ, _, found := strings.Cut(p.tok, ":"); found {
		if _, found2 := globalType[typ]; found2 {
			p.syntaxErr("Expected '}'")
		}
	}
	return p.attribute()
}

func (p *parser) topListHead() ast.TopBase {
	var a ast.TopBase
	a.SetPreComment(p.readPreCmt(""))
	a.Name = p.tok
	p.next()
	p.expect("=")
	a.Description = p.description()
	return a
}

func (p *parser) topList() ast.Toplevel {
	a := new(ast.TopList)
	a.TopBase = p.topListHead()
	a.Elements, _ = p.union(";")
	return a
}

func (p *parser) protocolgroup() ast.Toplevel {
	a := new(ast.Protocolgroup)
	a.TopBase = p.topListHead()
	a.ValueList = p.valueList((*parser).protocolRef, (*parser).next)
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
	p.expect(";")
	return a
}

func (p *parser) namedUnion() *ast.NamedUnion {
	a := new(ast.NamedUnion)
	a.SetPreComment(p.readPreCmt(""))
	a.SetPostComment(p.readPostCmtAfter("=;"))
	a.Name = p.name()
	p.expect("=")
	a.Elements, _ = p.union(";")
	return a
}

func (p *parser) rule() *ast.Rule {
	a := new(ast.Rule)
	a.SetPreComment(p.readPreCmt(""))
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
		if p.tok == "log" {
			a.Log = p.attribute()
		}
	default:
		p.syntaxErr("Expected 'permit' or 'deny'")
	}
	return a
}

func (p *parser) topStructHead() ast.TopStruct {
	var a ast.TopStruct
	a.SetPreComment(p.readPreCmt(""))
	a.SetPostComment(p.readPostCmtAfter("={"))
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
	u.SetPreComment(p.readPreCmt(""))
	u.SetPostComment(p.readPostCmtAfter("=;"))
	p.expectLeave("user")
	u.Name = p.name()
	p.expect("=")
	if p.check("foreach") {
		a.Foreach = true
	}
	u.Elements, _ = p.union(";")
	a.User = u
	for !p.check("}") {
		a.Rules = append(a.Rules, p.rule())
	}
	return a
}

func (p *parser) topStructWithChilds(
	prefix string) (ast.TopStruct, []*ast.Attribute, []*ast.Attribute) {

	top := p.topStructHead()
	var attr, childs []*ast.Attribute
	for !p.check("}") {
		if strings.HasPrefix(p.tok, prefix) {
			if len(p.tok) == len(prefix) {
				p.syntaxErr("Typed name expected")
			}
			childs = append(childs, p.attribute())
		} else {
			attr = append(attr, p.attributeNoToplevel())
		}
	}
	return top, attr, childs
}

func (p *parser) network() ast.Toplevel {
	a := new(ast.Network)
	a.TopStruct, a.Attributes, a.Hosts = p.topStructWithChilds("host:")
	return a
}

func (p *parser) router() ast.Toplevel {
	a := new(ast.Router)
	a.TopStruct, a.Attributes, a.Interfaces = p.topStructWithChilds("interface:")
	return a
}

func (p *parser) area() ast.Toplevel {
	a := new(ast.Area)
	a.TopStruct = p.topStructHead()
	for !p.check("}") {
		if p.tok == "border" {
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
	for !p.check("}") {
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
	var result []ast.Toplevel
	for p.tok != "" {
		result = append(result, p.toplevel())
	}
	return result
}

// A bailout panic is raised to indicate early termination.
type bailout struct {
	err error
}

func (p *parser) abort(e error) {
	panic(bailout{err: e})
}

func handlePanic(f func()) (err error) {
	defer func() {
		if e := recover(); e != nil {
			b := e.(bailout)
			err = b.err
		}
	}()
	f()
	return
}

func ParseFile(src []byte, fName string, mode Mode) (f *ast.File, err error) {
	err = handlePanic(func() {
		p := new(parser)
		p.init(src, fName, mode)
		f = new(ast.File)
		f.Nodes = p.file()
		if p.parseComments {
			f.BottomCmt = p.scanner.PreCmt(len(src), "")
		}
	})
	return
}

func ParseUnion(src []byte) (l []ast.Element, err error) {
	err = handlePanic(func() {
		p := new(parser)
		src = append(src, ';')
		p.init(src, "command line", 0)
		list, end := p.union(";")
		if end != len(src) {
			p.syntaxErr(`Unexpected content after ";"`)
		}
		l = list
	})
	return
}

func ParseAttribute(src []byte) (a *ast.Attribute, err error) {
	err = handlePanic(func() {
		p := new(parser)
		p.init(src, "command line", 0)
		a = p.attribute()
		if p.pos != len(src) {
			p.syntaxErr(`Unexpected content after attribute`)
		}
	})
	return
}

func ParseRule(src []byte) (r *ast.Rule, err error) {
	err = handlePanic(func() {
		p := new(parser)
		p.init(src, "command line", 0)
		r = p.rule()
		if p.pos != len(src) {
			p.syntaxErr(`Unexpected content after rule`)
		}
	})
	return
}

func ParseToplevel(src []byte) (n ast.Toplevel, err error) {
	err = handlePanic(func() {
		p := new(parser)
		p.init(src, "command line", 0)
		n = p.toplevel()
		if p.pos != len(src) {
			p.syntaxErr(`Unexpected content after definition`)
		}
	})
	return
}

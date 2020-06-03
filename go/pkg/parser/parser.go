// Package parser implements a parser for source files of Netspoc
// policy language.  Input may be provided in a variety of forms (see
// the various Parse* functions); the output is an abstract syntax
// tree (AST) representing the Netspoc source. The parser is invoked
// through one of the Parse* functions.
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
	scanner scanner.Scanner
	fname   string

	// Next token
	pos int    // token position
	tok string // token literal, one token look-ahead
}

func (p *parser) init(src []byte, fname string) {
	p.scanner.Init(src, fname)
	p.fname = fname

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
	start := p.pos
	p.next()
	a := new(ast.NamedRef)
	a.Start = start
	a.Typ = typ
	a.Name = name
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
	i := strings.Index(name, ".")
	if i == -1 {
		p.syntaxErr("Interface name expected")
	}
	router := name[:i]
	net := name[i+1:]
	err := !isRouterName(router)
	start := p.pos
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
	a := new(ast.IntfRef)
	a.Start = start
	a.Typ = typ
	a.Router = router
	a.Network = net   // If Network is "",
	a.Extension = ext // then Extension contains selector.
	a.Next = end
	return a
}

func (p *parser) simpleAuto(start int, typ string) ast.Element {
	list, end := p.union("]")
	a := new(ast.SimpleAuto)
	a.Start = start
	a.Typ = typ
	a.Elements = list
	a.Next = end
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
	var n *net.IPNet
	if p.check("ip") {
		p.check("=")
		n = p.ipPrefix()
		p.expect("&")
	}
	list, end := p.union("]")
	a := new(ast.AggAuto)
	a.Start = start
	a.Typ = typ
	a.Net = n
	a.Elements = list
	a.Next = end
	return a
}

func (p *parser) intfAuto(start int, typ string) ast.Element {
	m := false
	if p.check("managed") {
		m = true
		p.expect("&")
	}
	list, _ := p.union("]")
	p.expect(".[")
	s, end := p.selector()
	a := new(ast.IntfAuto)
	a.Start = start
	a.Typ = typ
	a.Managed = m
	a.Selector = s
	a.Elements = list
	a.Next = end
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
		el := p.extendedName()
		a := new(ast.Complement)
		a.Start = start
		a.Element = el
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
		a.List = intersection
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
	union = append(union, p.intersection())
	var end int

	for {
		if end = p.checkPos(stopToken); end >= 0 {
			break
		}
		p.expect(",")

		// Allow trailing comma.
		if end = p.checkPos(stopToken); end >= 0 {
			break
		}
		union = append(union, p.intersection())
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

func (p *parser) group() ast.Toplevel {
	a := new(ast.Group)
	a.Start = p.pos
	a.Name = p.tok
	p.next()
	p.expect("=")
	a.Description = p.description()
	if a.Next = p.checkPos(";"); a.Next < 0 {
		a.Elements, a.Next = p.union(";")
	}
	return a
}

func (p *parser) name() string {
	result := p.tok
	p.next()
	return result
}

func (p *parser) assignNameList() ([]string, int) {
	p.expect("=")
	var list []string
	list = append(list, p.name())
	var end int
	for {
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		p.expect(",")

		// Allow trailing comma.
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		list = append(list, p.name())
	}
	return list, end
}

func (p *parser) attribute() *ast.Attribute {
	a := new(ast.Attribute)
	a.Start = p.pos
	a.Name = p.name()
	if a.Next = p.checkPos(";"); a.Next < 0 {
		a.Values, a.Next = p.assignNameList()
	}
	return a
}

func (p *parser) protoDetail() (string, int) {
	token := p.tok
	start := p.pos
	switch token {
	case ":", "-":
	default:
		_, err := strconv.Atoi(p.tok)
		if err != nil {
			p.syntaxErr("Number expected")
		}
	}
	p.nextPort()
	return token, start + len(token)
}

func (p *parser) protoDetails() ([]string, int) {
	var result []string
	var end int
	for {
		if p.tok == "," || p.tok == ";" {
			break
		}
		token, after := p.protoDetail()
		result = append(result, token)
		end = after
	}
	return result, end
}

func (p *parser) simpleProtocol() *ast.SimpleProtocol {
	a := new(ast.SimpleProtocol)
	a.Start = p.pos
	a.Proto = p.tok
	p.nextPort()
	a.Details, a.Next = p.protoDetails()
	if a.Details == nil {
		a.Next = a.Start + len(a.Proto)
	}
	return a
}

func (p *parser) protocol() ast.Protocol {
	start := p.pos
	if typ, name := p.checkTypedName(); typ != "" {
		a := new(ast.NamedRef)
		a.Start = start
		a.Typ = typ
		a.Name = name
		return a
	}
	return p.simpleProtocol()
}

func (p *parser) protoList() ([]ast.Protocol, int) {
	var list []ast.Protocol
	list = append(list, p.protocol())
	var end int
	for {
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		p.expect(",")

		// Allow trailing comma.
		if end = p.checkPos(";"); end >= 0 {
			break
		}
		list = append(list, p.protocol())
	}
	return list, end
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
		p.expect("src")
		p.expect("=")
		a.Src, _ = p.union(";")
		p.expect("dst")
		p.expect("=")
		a.Dst, _ = p.union(";")
		p.expect("prt")
		p.expect("=")
		a.Prt, a.Next = p.protoList()
		if p.check("log") {
			p.expect("=")
			a.Log, a.Next = p.assignNameList()
		}
	default:
		p.syntaxErr("Expected 'permit' or 'deny'")
	}
	return a
}

func (p *parser) service() ast.Toplevel {
	a := new(ast.Service)
	a.Start = p.pos
	a.Name = p.tok
	p.next()
	p.expect("=")
	p.expect("{")
	a.Description = p.description()
ATTR:
	for {
		switch p.tok {
		case "user":
			break ATTR
		default:
			a.Attributes = append(a.Attributes, p.attribute())
		}
	}
	p.expect("user")
	p.expect("=")
	if p.check("foreach") {
		a.Foreach = true
	}
	a.User, _ = p.union(";")
RULES:
	for {
		switch p.tok {
		case "}":
			a.Next = p.pos
			p.next()
			break RULES
		default:
			a.Rules = append(a.Rules, p.rule())
		}
	}
	return a
}

var globalType = map[string]func(*parser) ast.Toplevel{
	//	"router":  parser.router,
	//	"network": parser.network,
	//	"any":     parser.aggregate,
	//	"area":    parser.area,
	"service": (*parser).service,
	"group":   (*parser).group,
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
	ast.SetFname(p.fname)
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

func ParseFile(src []byte, fname string) []ast.Toplevel {
	p := new(parser)
	p.init(src, fname)
	return p.file()
}

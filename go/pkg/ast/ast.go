// Package ast declares the types used to represent syntax trees for Netspoc
// files.
//
package ast

import (
	"net"
	"strings"
)

// ----------------------------------------------------------------------------
// Interfaces
//
// There are 3 main classes of nodes: Toplevel nodes, Element nodes,
// and other Nodes.
//
// All nodes contain position information marking the beginning of
// the corresponding source text segment; it is accessible via the
// Pos accessor method. Nodes may contain additional position info
// for language constructs where comments may be found between parts
// of the construct (typically any larger, parenthesized subpart).
// That position information is needed to properly position comments
// when printing the construct.

type Node interface {
	Pos() int // position of first character belonging to the node
	End() int // position of first character immediately after the node
	Normalize()
}

type Element interface {
	Node
	getType() string
	getName() string
}

type Toplevel interface {
	Node
	GetDescription() *Description
	GetName() string
	IsList() bool
	FileName() string
	SetFileName(string)
}

// ----------------------------------------------------------------------------

type Base struct {
	Start int
}

func (a *Base) Pos() int { return a.Start }

type withEnd struct {
	Next int
}

func (a *withEnd) End() int { return a.Next }

type User struct {
	Base
}

func (a *User) End() int        { return a.Pos() + len("user") }
func (a *User) getType() string { return "" }
func (a *User) getName() string { return "" }

type TypedElt struct {
	Base
	Typ string
}

func (a *TypedElt) getType() string { return a.Typ }
func (a *TypedElt) getName() string { return "" }

type NamedRef struct {
	TypedElt
	Name string
}

func (a *NamedRef) End() int {
	return a.Pos() + len(a.Typ) + 1 + len(a.Name)
}
func (a *NamedRef) getName() string { return a.Name }

type IntfRef struct {
	TypedElt
	withEnd
	Router    string
	Network   string
	Extension string
}

func (a *IntfRef) getName() string {
	r := a.Router + "." + a.Network
	if e := a.Extension; e != "" {
		r += "." + e
	}
	return r
}

type SimpleAuto struct {
	TypedElt
	withEnd
	Elements []Element
}

type AggAuto struct {
	SimpleAuto
	Net *net.IPNet
}
type IntfAuto struct {
	SimpleAuto
	Managed  bool
	Selector string
}

type Complement struct {
	Base
	Element Element
}

func (a *Complement) End() int        { return a.Element.End() }
func (a *Complement) getType() string { return "" }
func (a *Complement) getName() string { return "" }

type Intersection struct {
	Base
	Elements []Element
}

func (a *Intersection) End() int {
	return a.Elements[len(a.Elements)-1].End()
}
func (a *Intersection) getType() string { return a.Elements[0].getType() }
func (a *Intersection) getName() string { return a.Elements[0].getType() }

type Description struct {
	Base
	withEnd
	Text string
}

type TopBase struct {
	Base
	withEnd
	Name        string
	Description *Description
	fileName    string
}

func (a *TopBase) GetName() string              { return a.Name }
func (a *TopBase) GetDescription() *Description { return a.Description }
func (a *TopBase) FileName() string             { return a.fileName }
func (a *TopBase) SetFileName(n string)         { a.fileName = n }

type TopList struct {
	TopBase
	Elements []Element
}

func (a *TopList) IsList() bool { return true }

type Protocolgroup struct {
	TopBase
	ValueList []*Value
}

func (a *Protocolgroup) IsList() bool { return true }

type Protocol struct {
	TopBase
	Value string
}

func (a *Protocol) IsList() bool { return true }

type TopStruct struct {
	TopBase
	Attributes []*Attribute
}

func (a *TopStruct) IsList() bool { return false }

type Value struct {
	Base
	Value string
}

func (a *Value) End() int { return a.Pos() + len(a.Value) }

// Define methods of interface 'Elements', so we can sort and output
// attribute values like other elements.
func (a *Value) getType() string {
	i := strings.Index(a.Value, ":")
	if i == -1 {
		return ""
	}
	return a.Value[:i]
}
func (a *Value) getName() string {
	return a.Value[strings.Index(a.Value, ":")+1:]
}

type Attribute struct {
	Base
	withEnd
	Name string
	// Only one of those fields may be filled.
	ValueList    []*Value
	ComplexValue []*Attribute
}

type NamedUnion struct {
	Base
	withEnd
	Name     string
	Elements []Element
}

type Rule struct {
	Base
	withEnd
	Deny bool
	Src  *NamedUnion
	Dst  *NamedUnion
	Prt  *Attribute
	Log  *Attribute
}

type Service struct {
	TopStruct
	User    *NamedUnion
	Foreach bool
	Rules   []*Rule
}

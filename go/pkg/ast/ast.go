// Package ast declares the types used to represent syntax trees for Netspoc
// files.
//
package ast

import (
	"net"
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
	Order()
}

type Element interface {
	Node
	GetType() string
	GetName() string
}

type Toplevel interface {
	Node
	GetName() string
	SetName(string)
	GetDescription() *Description
	IsStruct() bool
	FileName() string
	SetFileName(string)
	GetIPV6() bool
	SetIPV6()
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
func (a *User) GetType() string { return "" }
func (a *User) GetName() string { return "" }

type TypedElt struct {
	Base
	Type string
}

func (a *TypedElt) GetType() string { return a.Type }
func (a *TypedElt) GetName() string { return "" }

type NamedRef struct {
	TypedElt
	Name string
}

func (a *NamedRef) End() int {
	return a.Pos() + len(a.Type) + 1 + len(a.Name)
}
func (a *NamedRef) GetName() string { return a.Name }

type IntfRef struct {
	TypedElt
	withEnd
	Router    string
	Network   string
	Extension string
}

func (a *IntfRef) GetName() string {
	n := a.Router + "." + a.Network
	if a.Network == "[" {
		n += a.Extension + "]"
	} else if e := a.Extension; e != "" {
		n += "." + e
	}
	return n
}

type SimpleAuto struct {
	TypedElt
	withEnd
	Elements []Element
}

func (a *SimpleAuto) GetElements() []Element { return a.Elements }

type AggAuto struct {
	SimpleAuto
	Net *net.IPNet
}
type IntfAuto struct {
	SimpleAuto
	Managed  bool
	Selector string
}

type AutoElem interface {
	GetType() string
	GetElements() []Element
}

type Complement struct {
	Base
	Element Element
}

func (a *Complement) End() int        { return a.Element.End() }
func (a *Complement) GetType() string { return "" }
func (a *Complement) GetName() string { return "" }

type Intersection struct {
	Base
	Elements []Element
}

func (a *Intersection) End() int {
	return a.Elements[len(a.Elements)-1].End()
}
func (a *Intersection) GetType() string { return a.Elements[0].GetType() }
func (a *Intersection) GetName() string { return a.Elements[0].GetType() }

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
	IPV6        bool
}

func (a *TopBase) IsStruct() bool               { return false }
func (a *TopBase) GetName() string              { return a.Name }
func (a *TopBase) SetName(n string)             { a.Name = n }
func (a *TopBase) GetDescription() *Description { return a.Description }
func (a *TopBase) FileName() string             { return a.fileName }
func (a *TopBase) SetFileName(n string)         { a.fileName = n }
func (a *TopBase) GetIPV6() bool                { return a.IPV6 }
func (a *TopBase) SetIPV6()                     { a.IPV6 = true }

type TopList struct {
	TopBase
	Elements []Element
}

type Protocolgroup struct {
	TopBase
	ValueList []*Value
}

type Protocol struct {
	TopBase
	Value string
}

type TopStruct struct {
	TopBase
	Attributes []*Attribute
}

func (a *TopStruct) IsStruct() bool { return true }

type Value struct {
	Base
	Value string
}

func (a *Value) End() int { return a.Pos() + len(a.Value) }

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

type Network struct {
	TopStruct
	Hosts []*Attribute
}

type Router struct {
	TopStruct
	Interfaces []*Attribute
}

type Area struct {
	TopStruct
	Border          *NamedUnion
	InclusiveBorder *NamedUnion
}

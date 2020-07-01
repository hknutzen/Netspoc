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
// There are 3 main classes of nodes: Expressions and type nodes,
// statement nodes, and declaration nodes. The node names usually
// match the corresponding Go spec production names to which they
// correspond. The node fields correspond to the individual parts
// of the respective productions.
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
	Fname() string
	SetFname(string)
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
	fname       string
}

func (a *TopBase) GetName() string              { return a.Name }
func (a *TopBase) GetDescription() *Description { return a.Description }
func (a *TopBase) IsList() bool                 { return false }
func (a *TopBase) Fname() string                { return a.fname }
func (a *TopBase) SetFname(n string)            { a.fname = n }

type TopList struct {
	TopBase
	Elements []Element
}

func (a *TopList) IsList() bool { return true }

type Group struct {
	TopList
}

type Value struct {
	Base
	Value string
}

func (a *Value) End() int { return a.Pos() + len(a.Value) }

// Define methods of interface 'Elements', so we can sort and output
// attribute values like other elements.
func (a *Value) getType() string { return "" }
func (a *Value) getName() string { return a.Value }

type Attribute struct {
	Base
	withEnd
	Name   string
	Values []*Value
}

type SimpleProtocol struct {
	Base
	withEnd
	Proto   string
	Details []string
}

// Define methods of interface 'Elements', so we can sort and output
// simple protocols together with named protocols and protocolgroups.
func (a *SimpleProtocol) getType() string { return "" }
func (a *SimpleProtocol) getName() string { return a.Proto }

type Rule struct {
	Base
	withEnd
	Deny bool
	Src  []Element
	Dst  []Element
	Prt  []Element
	Log  *Attribute
}

type Service struct {
	TopBase
	Attributes []*Attribute
	User       []Element
	Foreach    bool
	Rules      []*Rule
}

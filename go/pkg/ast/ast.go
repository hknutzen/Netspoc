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

// All node types implement the Node interface.
type Node interface {
	Pos() int // position of first character belonging to the node
	End() int // position of first character immediately after the node
}

// All element nodes implement the Element interface.
type Element interface {
	Node
	//	ElemNode()
}

// All toplevel nodes implement the Toplevel interface.
type Toplevel interface {
	Node
	SetFname(string)
}

// ----------------------------------------------------------------------------

type Base struct {
	Start int
	Next  int
}

func (a *Base) Pos() int { return a.Start }
func (a *Base) End() int { return a.Next }

type User struct {
	Base
}

func (a *User) End() int { return a.Pos() + len("user") }

type TypedElt struct {
	Base
	Typ string
}

type NamedRef struct {
	TypedElt
	Name string
}

func (a *NamedRef) End() int { return a.Pos() + len(a.Typ) + 1 + len(a.Name) }

type IntfRef struct {
	TypedElt
	Router    string
	Network   string
	Extension string
}

type SimpleAuto struct {
	TypedElt
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

func (a *Complement) End() int { return a.Element.End() }

type Intersection struct {
	Base
	List []Element
}

func (a *Intersection) End() int { return a.List[len(a.List)-1].End() }

type Description struct {
	Base
	Text string
}

type TopBase struct {
	Base
	Name        string
	Description *Description
	fname       string
}

func (a *TopBase) Fname() string     { return a.fname }
func (a *TopBase) SetFname(n string) { a.fname = n }

type TopList struct {
	TopBase
	Elements []Element
}

type Group struct {
	TopList
}

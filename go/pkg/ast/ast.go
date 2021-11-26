// Package ast declares the types used to represent syntax trees for Netspoc
// files.
//
package ast

import ()

// ----------------------------------------------------------------------------
// Interfaces
//
// There are 3 main classes of nodes: Toplevel nodes, Element nodes,
// and other Nodes.

type Node interface {
	PreComment() string  // Comment in line(s) before node, if available.
	PostComment() string // Trailing comment, if available.
	SetPreComment(string)
	SetPostComment(string)
	Order()
}

type Element interface {
	Node
	GetType() string
}

type Toplevel interface {
	Node
	GetName() string
	SetName(string)
	GetDescription() *Description
	FileName() string
	SetFileName(string)
	GetIPV6() bool
	SetIPV6()
}

// ----------------------------------------------------------------------------

type Base struct {
	preCmt  string
	postCmt string
}

func (a *Base) PreComment() string      { return a.preCmt }
func (a *Base) PostComment() string     { return a.postCmt }
func (a *Base) SetPreComment(c string)  { a.preCmt = c }
func (a *Base) SetPostComment(c string) { a.postCmt = c }

type User struct {
	Base
}

func (a *User) GetType() string { return "user" }

type TypedElt struct {
	Base
	Type string
}

func (a *TypedElt) GetType() string { return a.Type }

type NamedElem interface {
	GetType() string
	GetName() string
}

type NamedRef struct {
	TypedElt
	Name string
}

func (a *NamedRef) GetName() string { return a.Name }

type IntfRef struct {
	TypedElt
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
	Elements []Element
}

func (a *SimpleAuto) GetElements() []Element  { return a.Elements }
func (a *SimpleAuto) SetElements(l []Element) { a.Elements = l }

type AggAuto struct {
	SimpleAuto
	Net string
}
type IntfAuto struct {
	SimpleAuto
	Managed  bool
	Selector string
}

type AutoElem interface {
	GetType() string
	GetElements() []Element
	SetElements([]Element)
}

type Complement struct {
	Base
	Element Element
}

func (a *Complement) GetType() string { return "" }

type Intersection struct {
	Base
	Elements []Element
}

func (a *Intersection) GetType() string { return a.Elements[0].GetType() }

type Description struct {
	Base
	Text string
}

type TopBase struct {
	Base
	Name        string
	Description *Description
	fileName    string
	IPV6        bool
}

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

type Value struct {
	Base
	Value string
}

type Attribute struct {
	Base
	Name string
	// Only one of those fields may be filled.
	ValueList    []*Value
	ComplexValue []*Attribute
}

type NamedUnion struct {
	Base
	Name     string
	Elements []Element
}

type Rule struct {
	Base
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

// ----------------------------------------------------------------------------

type File struct {
	Nodes     []Toplevel
	BottomCmt string
}

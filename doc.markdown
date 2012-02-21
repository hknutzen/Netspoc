# Documentation


* Table of content
{:toc}


##Overview

###Service

- A service is a set of related rules. 
- Network objects and protocols are used in rules to
describe network traffic which can or must not pass from source to
destination.
- All rules of a single service must refer to the same network
objects in their source or destination.
- Services have a name which can be used for documentation or
reporting purposes.


###Network Objects

- Have name and IP address.
- Describe the topology.
- Can be used as source and destination of rules.


###Protocol Definitions

- have a name
- describe properties of network traffic as they typically can be
filtered by packet filters (i.e. type of protocol, port number)


###Groups

- have a name
- are used to group network objects
- are used in rules for simplified management of large numbers of
network objects.


###Protocol Groups

- have a name
- are used to group protocol definitions
- are used in rules


###Areas

The topology is build from networks and routers. Networks and routers are
connected by interfaces. 


An *area* denotes a part of the topology which is delimited by a set
of interfaces. Areas are used to access all networks or security domains of
some part of the topology.

###Crypto Definition

A <a href="#crypto_syntax">crypto definition</a> consists of two parts:

1. definition of crypto type (currently IPSec with ISAKMP).
1. Occurrences of hub and spoke attributes at interfaces which define
   the actual tunnels between many VPN spokes and one (or two redundant)
   VPN hubs. The referenced crypto type defines the to be used crypto
   details.

Crypto definitions are very powerful: A large number of crypto tunnels
of a hub and spoke topology can be defined easily.

##Detailed description of network objects

The topology is built from networks and routers.
A router and a network are connected by an interface.
Networks can have any number of hosts, which are located inside the
network.

Routers can be managed or unmanaged. For a managed router, NetSPoC
generates access control lists which control what traffic can pass
this router and what traffic is blocked.
The whole topology is partitioned into different security domains by
managed routers.

Special network objects called 'any' objects can
be defined which denote all network objects inside a security domain.

###General syntax

All network objects and groups have a typed name like &lt;type&gt;:&lt;name&gt;.

&lt;name&gt; is build from one ore more alphanumerical characters together
with hyphen and underscore. The current locale settings are used,
i.e. accented characters are allowed for European locale settings.

&lt;ip-adr&gt; denotes an IP address. Currently NetSPoC handles IP v4
addresses n.n.n.n with 0 &lt;= n &lt;= 255

&lt;text_to_end_of_line&gt; is any text from current position up to end of
line.

&lt;external_name&gt; can contain almost any characters, but not
whitespace, no delimiters `[;,=]` and no quotes 
`["']`. 

&lt;int&gt; is an integer

Meta symbols in syntax definitions below:

- `<xx>` denote something defined elsewhere.
- `[[xx]]` denotes an optional part.  
  Note: single \[ and \] characters stand for themselves.
- `{{xx|yy}}` denotes alternatives.  
  Note: single { and } characters stand for themselves.
- `xx *` means any number of the left part.
- `xx, ...` means a comma separated list of one or more elements
of the left part.


###Network Definition
####Syntax

    network:<name> = {
       [[ owner = <external_name>, ... ; ]]
       {{
           ip = <ip-adr><mask>;
           <network NAT definition> *
           [[ route_hint; ]]
           [[ subnet_of = network:<name>; ]]
           <host definition> *
       |
           unnumbered
       }}
    }

with

    <network NAT definition> ::=
           nat:<name> = { 
            ip = <ip-adr>[[<mask>]];
            [[ dynamic; ]]
            [[ subnet_of = network:<name>; ]] 
           }

    <mask> ::= {{/<prefix-lenght> | ; mask = <ip-adr> }}
    <prefix-lenght> ::= {{ 0 | 1 | 2 | ... | 32 }}


- A network is described by an ip address and a mask or
- can alternatively be marked as unnumbered.
- It can contain any number of host definitions.
- Unnumbered networks must have no host definitions at all.
- If used as source or destination of a rule, the ip/mask is used
directly for generating ACLs.
- An unnumbered network must not be used in rules.
- All networks must be disjunct if option 'strict_subnets' is
active. This can be useful for a large topology, where a network can easily be
redefined by mistake.
Exceptions must be declared explictly:

  - route_hint: This network can enclose other networks, but it must
    not have host definitions and must not be used in rules.
  - subnet_of: The enclosing network is declared explicitly.


###Host definition
####Syntax

    <host definition> ::=
          host:<name> = { 
            [[ owner = <external_name>, ... ; ]]  
            {{
              ip = <ip-adr>;
            |
              range = <ip-adr> - <ip-adr>;
            }}
            [[ policy_distribution_point; ]]
            <NAT definition> *
          }

    <NAT definition> ::=
          nat:<name> = { ip = <ip-adr>; }


- A host can only be defined inside a network definition.
- It has one IP address or
- alternatively an ip address range with first address < second address
- IP addresses must match ip/mask of the surrounding network.
- If used as source or destination of a rule, one ACL entry is
generated for each IP address.
- NetSPoC tries to automatically convert successive IP addresses from one
or multiple hosts of a common network to an IP range.
- During code generation, an IP range is split into a number of
subnetworks which cover the range. One ACL entry is generated for
each subnetwork.
- A single host inside the topology can be marked as
"policy_distribution_point". This should be set to the device, which
distributes the NetSPoC generated configuration to the packet filters.
This allows Netspoc to know by which IP address a device is reached
from the policy distribution point. This IP address is added as a
comment to each generated device configuration. It can later be used to
reach the device when deploying the configuration.


###Router definition
####Syntax

    <router definition> ::=
    router:<name> = {
       {{
          managed [[ = {{ primary | full | standard | secondary }} ]] ;
          model = <name>;
          [[ no_group_code; ]]
          [[ no_crypto_filter; ]]
          <interface definition> *
       |
          [[ model = <name>; ]]
          {{ 
             <interface definition> 
          | 
             <short interface definition> 
          }} *
       }}
    }

- A router can be managed or unmanaged.
- Managed routers can be of type 'primary', 'full', 'standard' or 
of type 'secondary'. A type 'standard' is assumed, if no value is given. 
See <A HREF="#secondary_packet_filters">secondary packet filters</A> below for a detailed
description. 
- Managed routers need to be precisely described since this
 information is needed for code generation later.
- The router model is used to generate correct code for different
 router models.  
 Currently these models are supported:

  - `Linux` for Linux with iptables,
  - `ASA` for Cisco ASA,
  - `ASA, VPN` for Cisco ASA with VPN tunnels authenticated
  by certificates,
  - `PIX` for Cisco PIX,
  - `IOS` for Cisco IOS routers,
  - `IOS, FW` for Cisco IOS routers with statefull inspection,
  - `IOS, EZVPN` for Cisco IOS routers with easy VPN,
  - `VPN3K` for Cisco VPN 3000 devices.

- NetSPoC generates optimized code using object groups for PIX firewalls. 
Use attribute `no_group_code` to disable this optimization.
- For ASA,VPN devices, filtering of incoming traffic of crypto
tunnels is done with a per vpn-filter. Use
attribute `no_crypto_filter` to enable "no sysopt
connection permit-vpn" which switches to filter the VPN traffic at the
interface ACL. This attribute must be activated, if statefull
filtering is needed.
- For IOS routers from version 12.3(8)T up, a separate access-list is used
for filtering incoming traffic of crypto tunnels. Use
attribute `no_crypto_filter` to enable the old behavior where
crypto traffic is filtered by access-lists of interfaces.
- A Router can have any number of interface definitions.
- For unmanaged routers, all attributes are optional.
- An interface definition without attributes is called a "short
interface definition".


###Interface definition
####Syntax

    <interface definition> ::= 
      interface:<name> = {
           {{ ip = <ip-adr>, ... ; | unnumbered; | negotiated; }}
           <secondary interface definition> *
           [[ <virtual interface definition> ]]
           <NAT definition> *
           [[ <NAT binding> ]]
           [[ hardware = <external_name> ; ]]
           [[ routing = {{ EIGRP | OSPF | manual }} ; ]]
           [[ reroute_permit = network:<name>, ... ; ]]
           [[ loopback ; [[ subnet_of = network:<name>; ]] ]]
           [[ disabled ; ]]
      }

    <secondary interface definition> ::=
      secondary:<name> = { 
           ip = <ip-adr>;
      }

    <virtual interface definition> ::=
      virtual = { 
           ip = <ip-adr>;
           type = {{ VRRP | HSRP }};
           [[ id = <int>; ]]
      }

    <NAT definition> ::=
      nat:<name> = { ip = <ip-adr>; }
    <NAT binding> ::=
      bind_nat = <name>, ... ;

    <short interface definition> ::=
      interface:<name>;


- Interfaces have no name of their own; instead a network name is used
  to indicate that the interface is linked to a network of the same
  name.
- An interface can have one or more IP addresses. All of them must
  match the IP/mask of the corresponding network.
- An unnumbered interface must only be linked to an unnumbered network.
- A negotiated interface has an unknown IP address out of the attached
  network. If an interface with negotiated IP is used in a rule, the address
  range of the attached network is used.
- Additional IP addresses can be defined using a secondary
  interface. A secondary interface is referenced as
  `interface:<router-name>.<network-name>.<secondary-name>`
- Another method to define secondary interfaces is by giving two or more IP
  addresses to the primary interface. This implicitly defines secondary
  interfaces with a name which is derived from the name of the primary
  interface by adding an incrementing number beginning with "2".
  E.g. `interface:router.name.2, interface:router.name.3, ...`.
- A virtual interface defines a shared IP address and type of redundancy
  protocol. See <a href="#virtual_interface"> Virtual interfaces</a> for details.
- The 'hardware' attribute indicates, which hardware interface the router
  belongs to. This attribute is mandatory for managed routers.
- Multiple interfaces can belong to the same hardware interface.
- A routing protocol can be activated for an interface. In this
 case, generation of static routing entries is disabled for this
 interface and access control lists for this interface are automatically
 augmented to permit incoming packets of the routing
 protocol. Currently EIGRP and OSPF are supported.
- If `routing=manual`, no routing code is generated at all. Some
  other means has to be used to configure routing for this interface.
-  For a description of attribute 'reroute_permit', 
 see <a href="#rerouting">Rerouting inside of security domains</a> below.
-  Use attribute 'loopback' to define a loopback interface. A
 loopback interface is not linked to a network, but only used as an
 additional address of a router. Loopback interfaces of different
 routers may share the same name, e.g. interface:r1.loop and
 interface:r2.loop.
- subnet_of: The enclosing network is declared explicitly.
- An interface can be marked as disabled.
  See <A HREF="#disabling">Disabling part of the topology</A> below.
- For interface definitions of unmanaged routers all attributes
  can be left out.
- An interface definition without any attributes is called a "short
  interface definition".
-  A short interface can only be used if there is no managed
  interface with static routing enabled in the same network. We need
  this requirement for getting all routing entries generated.
- An interface is handled like a host if it is used as source or
  destination of a rule.



###'Any' object definition
####Syntax

    any:<name> = { 
        [[ owner = <external_name>, ... ; ]]
        link = {{ 
                  network:<name>; 
               |  
                  router:<name>; 
               }} 
    }

- An 'any' definition is used to represent all networks of a security domain.
- It must not be linked to a managed router.
- At most one 'any' object can be defined for a security domain.
- Generated ACLs use 'any' (i.e. network 0.0.0.0/0.0.0.0) to prevent
enumeration of all networks of a security domain.
- NetSPoC checks that additional any rules are definet to ensure that
intervening networks get access as well.
- See <A HREF="#handling_any">Handling of 'any' objects</A> for details.


###Area definition
####Syntax

    area:<name> = {
     [[ owner = <external_name>, ... ; ]]
     [[ auto_border; ]]
     {{ 
       border = <object set> ; 
     | anchor = network:<name>;
     }}
    }

- Use attribute `border` to define interfaces which are the
border of the area.
- Alternatively use attribute `anchor` to define a starting point
from where the area extends. Typically `anchor` is used together
with attribute `auto_border` which restricts the area to the border
of other areas. 
- Use attribute `anchor` without `auto_border` to
define an area which stretches across the whole topology.
- Exactly one attribute of `border` and `anchor` must
be choosen.
- Only interfaces of managed routers must be given as `border`.



###Referencing single or sets of network objects
####Syntax

    <object set> ::= 
       {{ <network object> | <intersection> }} , ...
    <intersection> ::= 
       <network object>  &  <complement> [[ & <complement> ...]]
    <complement> ::=
       [[!]] <network object>

    <network object> ::=
    {{
      host:<name> 
    | network:<name>
    | any:<name> 
    | interface:<name>.<name>[[.<name>]]
    | group:<name> 
    | <auto group>
    }}

- An &lt;object set&gt; is used to define a set of elements. 
- In the simplest case it is the union of comma separated
&lt;network object&gt;'s. 
- More complicated sets can be build using intersection and
complement. Intersection and complement is typically used to 
remove some elements from a given group of elements.
There are two restrictions:
  1. least one subexpression must not be complemented.
  2. elements of the subexpressions must be of same type.
- &lt;object set&gt;'s are used to define groups or as source or destination
of rules.
-  Hosts, networks and 'any' objects are referenced by the name of
their respective definition.
- When referencing interfaces, we need to use a different syntax
than for interface definitions: the router name followed by a network
name.  
- The name for referencing secondary interfaces has three parts: the
router name, the network name and the name of the secondary interface
from its definition.
- A reference to a group is substituted by the elements of the [group definition](#groups_of_network_objects).
- So called [automatic groups](#automatic_groups) are used to
reference network objects from particular parts of the topology.



###Automatic groups
####Syntax

    <auto group> ::=
    {{
      interface:<name>.[<selector>]
    | interface:[ [[ managed & ]] <object set with area>].[<selector>]
    | network:[<object set with area>] 
    | any:[<object set with area>]
    }}

    <selector> ::= {{ auto | all }}
    <object set with area> is like <object set> 
      but with additional area:<name> in <network object>

- Special names \[auto\] and \[all\] can be used as network part in a
  reference to an interface.

  - \[auto\] denotes the interface on the same side in respect to the
    other object in a rule.  If a router is part of a cyclic subgraph
    then there can be multiple paths to the other object.  In this
    case \[auto\] denotes multiple interfaces.
  - \[all\] denotes *all* interfaces of a router.  
    But note: Short interfaces (without known IP address) of unmanaged routers
    are excluded.

- \[managed & ...\] restricts the result to interfaces of *managed*
routers.
- `interface`, ` network ` or ` any
` applied to a set of objects is equivalent to applying these to
the single elements and taking the union of results. E.g. `
network:[host:a, host:b] ` is equivalent to ` network:[host:a],
network:[host:b] `.

- `interface:[network:x].[<selector>]` takes
some or all interfaces of network:x.

- `interface:[interface:x.y].[<selector>]` is
equivalent to `interface:x.<selector>`.

- `interface:[any:x].[all]` takes all border interfaces
of security domain any:x.

- `interface:[area:x].[<selector>]` takes
interfaces which are located *inside* area:x.  
  Note: Border interfaces are left out.

- `network:[interface:x.y]` takes the network attached to
interface:x.y.

- `network:[host:x]` takes the network where host:x is located.

- `network:[network:x]` is equivalent to
`network:x`.

- `network:[any:x]` takes all networks located inside security
domain any:x.

- `network:[area:x]` takes all networks located inside
area:x.

- `any:[interface:x.y], any:[host:x], any:[network:x],
any:[any:x]` takes the security domain where the inner object is
located.

- `any:[area:x]` takes all secutrity domains located
inside area:x.

- Auto interfaces, i.e. with selector \[auto\] must only be
  used at toplevel and not as inner object of other automatic
  groups. There is one exception from this rule: `
  interface:[interface:x.[auto]].[auto] ` is
  allowed.



###Groups of network objects
####Syntax 
    group:<name> = <object set>;

- A group can be empty 
- A group can be defined by means of other groups 

###Protocols
####Syntax

    protocol:<name> = 
    {{
      ip 
    | tcp [[[[<range> :]] <range>]]
    | udp [[[[<range> :]] <range>]]
    | icmp [[<int_1>[[/<int_2>]]]] 
    | proto <int> 
    }} [[<protocol modifier>]] ;

with

    <range> ::= <int_1>[[-<int_2>]]



tcp
udp

: -  A &lt;range> denotes a tcp/udp port range
  -  A &lt;range> consisting of only one number denotes a single
     port
  -  An empty &lt;range> is equivalent to the full range of all
     ports 1 - 65535 
  -  If only one  &lt;range> is given, it describes the destination
     port
  -  If two  &lt;range>s are given, they describe source and
     destination port
  - 0 &lt; &lt;int_1> <= &lt;int_2> <= 65535

icmp

: - &lt;int_1&gt;, &lt;int_2&gt; denote icmp type and code
  - 0 <= &lt;int_1&gt;,&lt;int_2&gt; <= 255

protocol

: - &lt;int&gt; is an IP protocol number
  - 0 < &lt;int&gt; <= 255


- For permitting a TCP connection from source to destination, only one rule
    is needed. Answer packets are automatically allowed. For stateful packet
    filters, this is done at the device. For stateless packet filters, netspoc
    automatically generates a rule which allowes any TCP traffic from
    destination to source with flag "established" i.e. no SYN flag set.

- Similarly, only one rule is needed to let UDP packets pass from source to
    destination and back. For stateless packet filters, a rule with reversed
    addresses and reversed port numbers is generated.

- For protocol IP and stateless packet filters, a rules with reversed
    addresses is generated. This is needed to get an unified handling for TCP,
    UDP and IP.



###Protocol modifiers

One or more &lt;protocol modifier&gt;'s can optionally be appended to a protocol
definition. A &lt;protocol modifier&gt; modifies the rule in which the
corresponding protocol is used as follows.


stateless
: The rule is only applied to stateless devices.

oneway
: At stateless devices, don't automatically generate rules
to permit answer packets.

reversed
:Source and destination are swapped.

dst_net
:If destination of rule is a host or interface, find the
enclosing network *n* and replace destination
by *n*. Exception: hosts having a vpn id and interfaces of
manged routers are left unchanged.

dst_any
:First apply rules of modifier dst_net above. If
afterwards destination of rule is a network, find the enclosing 'any'
object *a* and replace destination by
*a*.

src_net
src_any
:Equivalent to dst_* modifiers but applied to
source of rule.

###Groups of protocols
####Syntax

    protocolgroup:<name> = <protocol>, ... ;

with

    <protocol> ::= {{ protocol:<name> | protocolgroup:<name> }}

- A protocolgroup can be empty.
- A protocolgroup can be defined by means of other protocolgroups.


###Services
####Syntax

    service:<name> = {
       [[ description = <text_to_end_of_line> ]]
       user = [[ foreach ]] <object set>;
       <service_rule> * 
    }

with

    <service_rule> ::=
    {{ permit | deny }}
          src = <object set with 'user'>;
          dst = <object set with 'user'>;
          prt = <protocol>, ... ;
    <object set with 'user'> is like <object set> 
     but with additional keyword 'user' allowed in <network object>

- Order of rules doesn't matter.
- Deny rules override all permit rules.
- Services give a descriptive name to a group of related rules. 
- Services are useful for documentation and reporting purposes. 
- The rules of a service must be related in that they all use the same source
or destination object(s). This is enforced by the keyword "user" which
must be referenced either from src or from dst or both parts of a rule.
- Without the keyword "foreach", each occurrence of "user" is substituted 
by the definition of "user". This is typically a group of values.
- With the keyord "foreach", the substituton occurs repeatedly for 
each element of the definition of "user". Used together with automatic groups, 
this feature allows to define rules between elements and their neighborhood.


####Example

    service:ping_local = {
     description = Allow ping to my devices from directly attached network
     user = foreach interface:[group:my_devices].[all];
     permit src = network:[user]; dst = user; prt = protocol:ping;
    }

###Path restrictions
####Syntax

    pathrestriction:<name> = 
      [[ description = <text_to_end_of_line> ]]
      <object set> ;

 - Path restrictions are used to restrict paths inside cyclic
  subgraphs of the topology.
 - All paths running through two or more interfaces belonging to the
  same path restriction are discarded i. e. marked as invalid.
 - Path restrictions must not be used to discard *all* paths
  between some source / destination pair. Use a service with deny rules
  instead.
 - A path restriction must only be applied to interfaces located
   inside or at the border of a cyclic subgraph of the topology.
 - A path restriction is automatically added for each group of
   interfaces belonging to a VRRP or HSRP cluster.


###Global NAT definition
####Syntax

    nat:<name> = { 
      ip = <ip-adr><mask>; 
      dynamic;
      [[ subnet_of = network:<name>; ]] 
    }

with `<mask>` defined as [above](#network_definition)


A global NAT definition can be used as a shortcut for applying multiple
identical dynamic NAT definitions to all networks in some area. See <a
href="#NAT">network address translation</a> for details.

##Network address translation (NAT) {#NAT}

Network address translation occurs at routers.
At one side of a router, a network object is visible with its original
IP address; at another side of the router this address is translated
to another address.


Currently, NetSPoC supports static and dynamic NAT for whole
networks.


For static NAT, the translated address uses the same netmask as the
original network. The translation is automatically applied to all host and
interface definitions of the translated network. A separate NAT
definition for hosts or interfaces is not possible in this case.


For dynamic NAT, the translated address can use a different netmask than
the original network. Typically a smaller network is used for translation. IP
addresses are translated dynamically, hence hosts and interfaces of this
network are not visible from outside. But a dynamic translation of a network
can be augmented with static translations for single hosts or interfaces of
this network.


Syntax for NAT is divided into two parts:

1. *NAT definition* denominates the alternate IP address of an
network object.
2.A *NAT binding* applies a set of NAT definitions to an
interface. 

###Example

Network "extern" has bad IP addresses, which are not usable at network
"intern". At router "r_ext" static NAT occurs. The NAT definition and
NAT binding tells NetSPoC, that and where NAT occurs.
Hosts "extern_www" and "extern_mail" are visible with addresses
10.7.128.10 and 10.7.128.25 from "intern".

    network:extern = {
     ip = 128.1.2.0; mask = 255.255.255.0;
     # static NAT definition
     nat:bad128 = { ip = 10.7.128.0; }
     host:extern_www = { ip = 128.1.2.10; }
     host:extern_mail = { ip = 128.1.2.25; }
    }

    router:r_ext = {
     interface:extern;
     interface:intern = {
      ip = 10.1.1.1;
      # NAT binding
      bind_nat = bad128;
     }
    }

    network:intern = { ip = 10.1.1.0; mask = 255.255.255.0; }

All NAT definitions with the same name establish a set of NAT
definitions.  A set of NAT definition is effective *behind*
that interface where the NAT binding with the same name occurs. We are
defining *behind an interface* as that part of the topology
which is seen when looking from the router to that interface.


Multiple NAT definitions can be given for a single network. These are bound
to different interfaces to make different NAT definitions effective at
different parts of the topology.


Multiple NAT definitions can be bound to single interface. This
simplifies definition of NAT for devices with multiple interfaces.


For dynamic NAT, multiple networks can use identical NAT definitions. This
is used to masquerade multiple networks to a single address space.


A global NAT definition can be used as a shortcut for applying multiple
identical dynamic NAT definitions to all networks located *before* that
interface where the NAT binding with this name occurs.


NetSPoC needs to know about NAT for different reasons:

1. generating ACLs for an interface it must use those IP
    addresses which are visible in the area of this interface.
2. same is true when generating static routing entries.
3. some types of devices NetSPoC is able to actually generate the
   NAT translation rules. This is currently true for Cisco ASA and PIX devices.

##Secondary packet filters

In a given topology we can get chains of managed packet filters on the
path from src to dst. By default, each device filters the same rules
again and again.

A secondary packet filter gets a simpler rule set.

A given rule describes traffic starting at src and terminating at dst.
If there is at least one none secondary packet filter on the path from
src to dst, all secondary packet filters on this path get a simplified
ACL line for the current rule. This ACL line allows any IP packets
from the src network to the dst network. This simplified filtering
assures that the traffic comes from the right src and goes to the
right dst.


If, for a given rule, there is a chain of secondary packet filters without a
none secondary filter, all devices do standard filtering.


A secondary packet filter is declared with attribute
"managed = secondary". This can be useful if a router has not
enough memory for storing a complete set of filter rules and most of
the packets get fully filtered already by some other managed device.


If a device is marked as "managed = primary", all rules which pass
this device, are implemented as secondary filters on other devices
which are marked either as "standard" or as "secondary".  The effect
of "primary" can be overridden by choosing the filter type "full" at
an other device.  


The default filter type for devices which are simply marked as
"managed" is "standard".

##Outgoing ACL

Per default, NetSPoC generates incoming access lists at each interface
of a managed device. Use the attribute `no_in_acl` at one
interface, to move the incoming ACL from this interface to outgoing
ACLs at the other interfaces of the same device.


This is useful for situations like this:

1. packet filter connects multiple customers to some central
    site.  Each customer needs to inspect the ACls of 'his' interface,
    but must not see ACLs of the other customers.  Declaring the
    interface to the central site with 'no_in_acl' adds outgoing ACL
    to each customer interface.
2. packet filter has three interfaces A, B, C.  There is a rule
    `permit network:A -> any:[network:B]`. With only
    incoming ACLs, this would allow traffic "network:A ->
    any:\[network:C\]" as well.  With attribute 'no_in_acl' at interface
    A we get outgoing ACLs at interface B and C which permit traffic
    to any:\[network:B\] but not to any:\[network:C\].

For IOS there remains a minimal incoming ACL that filters traffic
for the device itself.


These restrictions apply:

- At most one interface with `no_in_acl` is allowed per
device.
- Multiple interfaces at the same hardware are not allowed if
  `no_in_acl` is declared at some logical interface of
  this hardware.
- `no_in_acl` must not be used together with crypto
  tunnels at the same device.
- All interfaces must equally use or not use outgoing ACLs at
  a <a href="#crosslink_network">crosslink network</a>.
- All interfaces with attribute `no_in_acl` at routers
  connected by a <a href="#crosslink_network">crosslink network</a> must be
  border of the same security domain.

Outgoing ACLs are supported for model IOS, Linux and ASA.  For
convenience, the attribute `no_in_acl` can be added to an 'any'
object. It is then inherited by all border interfaces of this 'any'
object. Inheritance is stopped for devices which already have an
attribute `no_in_acl` declared at some interface or have
an attribute `std_in_acl` declared at the device level.


##Routing

####Static and dynamic routing

From its knowledge about the topology, NetSPoC generates static
routing entries for each managed device. If an interface of a device
has an attribute "routing=&lt;routing protocol&gt;", no static routing
entries are generated for networks behind that interface.


Routing entries are only generated for network objects, which are
used in some rule. I.e. no routing entries are generated for unused
parts of the topology. Even for network objects which are only used as
source of a rule, routing entries are generated, since stateful packet
filters implicitly allow answer packets back to the source. If an
'any' object is used in a rule, routing entries for all networks part
of this 'any' object are generated.

####Default route

A default route can be defined for a topology by placing a network
with IP address and mask equal 0.0.0.0. Such a network must have an
attribute "route_hint".


Alternatively, NetSPoC can automatically define a default route for
each managed device as a means to reduce the number of static routing
entries. 

- At each managed device, a default route is automatically inserted such
that it replaces the maximum number of routing entries. 
- This behavior can be switched on or off by option --auto_default_route.
- This option must be switched off, if a user defined default route is
given.
- This behavior is automatically disabled for routers where at least one
interface has dynamic routing enabled. 


####Optimization
Multiple routing entries for networks which are in a subnet
relation, are replaced by a single routing entry.

##Rerouting inside of security domains {#rerouting}

Internal traffic which flows inside a security domain isn't
filtered at all. Sometimes an interface X of a managed (filtering)
router is used as a default route for traffic which normally flows
inside a security domain. This would cause internal traffic to be
routed to X, which would deny this traffic.


NetSPoC is prepared to handle this case by defining an attribute
'reroute_permit' for a managed interface. Value of this attribute is a
list of networks, for which any internal traffic should be allowed.

####Example
router:x is managed, router:y is unmanaged.

    router:x -- network:a -- router:y -- network:b



network:a and network:b are inside one security domain, since
router:y isn't managed. If traffic from network:a to network:b is
routed via router:x and router:y, router:x would deny this traffic.
Use "reroute_permit = network:b" at "interface:x.a" to permit any
incoming traffic to network:b.
 
##Virtual interface

A virtual interface defines a shared IP address and type of
redundancy protocol at two or more interfaces. Currently, redundancy
protocols VRRP and HSRP are supported.

-  The virtual IP address is used as destination when generating static
routes.
-  Access control lists for the associated real interfaces are
 automatically augmented to permit incoming packets of the redundancy
 protocol.
-  At least two interfaces with the same virtual IP are needed.
-  The set of interfaces with same virtual IP

-  must be linked to the same network and
-  must be part of the same cyclic subgraph.

-  A virtual IP must be different from real IP address(es).
- It is possible to define an interface having only a virtual IP,
but no real IP address.
-  The 'id' attribute is optional. It is used for consistency checks
but is currently not used when generating code for managed devices.


##Crosslink network

Add attribute `crosslink` to a define a  crosslink network.

A crosslink network combines two or more routers to a cluster of
  routers. Filtering occurs only at the outside interfaces of the
  cluster. The crosslink interfaces permit any traffic, because
  traffic has already been filtered by some other device of the
  cluster.  These characteristics are enforced for crosslink networks:

- No hosts must be defined inside a crosslink network.
- All attached routers are managed and have the same managed type
  (secondary, standard, full, primary).
- A hardware interface attached to a crosslink interface has no
  other logical networks attached.
- A crosslink network must not be used in rules.
- Crosslink networks are left out from network:\[area:xx\] and
  network:\[any:xx\].
- A crosslink network is removed silently from automatic networks
of an interface.


##Network with isolated ports


For a network with attribute `isolated_ports`, hosts inside
this network are not allowed to talk directly to each other. Instead
the traffic must go through an interface which is marked with
attribute `promiscuous_port`.  Non promiscuous interfaces
are isolated as well; they are handled like hosts.

##Disabling part of the topology {#disabling}

An interface can be explicitly marked as disabled.  This implicitly
marks all network objects as disabled, that are located *behind*
this interface. We are defining *behind an interface* as that
part of the topology which is seen when looking from the router to
that interface. All occurrences of disabled network objects in groups and
rules are silently discarded.

##Encryption

Encrypted VPN tunnels are supported for

1. access by tele worker with software VPN client,
2. access from remote office with hardware VPN client or
3. to LAN tunnel.

The type of encryption is defined by a ` crypto ` definition.

###Syntax {#crypto_syntax}

    crypto:<name> = {
       [[ description = <text_to_end_of_line> ]]
       type = ipsec:<name>;
       tunnel_all;
    }


    ipsec:<name> = {
       key_exchange = isakmp:<name>;
       esp_encryption = {{ aes | aes192 | aes256 | des | 3des | none }};
       esp_authentication = {{ md5_hmac | sha_hmac | none }};
       ah = {{ md5_hmac | sha_hmac | none }};
       pfs_group = {{ 1 | 2 | 5 | none}};
       lifetime = <number> <timeunit>;
    }

    isakmp:<name> = {
       identity = {{ address | fqdn }};
       nat_traversal = {{ on | additional | off }};
       authentication = {{ preshare | rsasig }};
       encryption = {{ aes | aes192 | aes256 | des | 3des }};
       hash = {{ md5 | sha }};
       group = {{ 1 | 2 | 5 }};
       lifetime = <number> <timeunit>;
    }

with

    <timeunit> ::= 
      {{ sec | min | hour | day | secs | mins | hours | days }};

The actual crypto tunnels are defined by adding `hub`
and `spoke` definitions to interfaces.

    interface:<name1> = {
      ..
      hub = crypto:<name>
    }

    interface:<name2> = {
      ..
      spoke = crypto:<name>
    }

model= ASA, VPN | VPN3K for remote access
with no_check, 
model = ASA for LAN to LAN
##Remote access

Tele worker

: - VPN software client
- authenticate itself by certificate
- dynamically get IP address from radius server via VPN device


Remote office

: - VPN router with attached network
- router authenticates traffic by certificate
- router has public IP address at outside interface
- router has fixed private IP address at inside interface
- fixed IP address range for attached network


Both

: - build VPN tunnel to central VPN device
- VPN device uses certificate name to authenticate at radius server
- radius server sends indivdual access list to VPN device
- VPN device permits authorized access for client


This concept has been implemented for Cisco ASA and VPN 3000 (VPN3K)
devices.  VPN3K send authorization request to one or more radius
servers. ASA uses a local user database. VPN is build using IPSec
tunnels.

###Cisco VPN 3000

new router model 
: model=VPN3K

additional attribute for router
: radius_servers=&lt;object set&gt;
additional attributes for interface
: - hub=crypto:&lt;name&gt; as described above
- no_check

additional syntax for hosts
: host:id:certificate-name

additional attribute for network
: id=&lt;user\[\[@domain\]\]&gt;

additional optional attribute at host with id, network with id, network having id hosts and router of type vpn3k
: radius_attributes={&lt;key&gt;=&lt;value&gt;;\*}


####Additional restrictions

- Router needs to have exactly one interface with attribute 'no_check'.
- Source of rule must have ID when entering interface without attribute 'no_check',

- Attribute 'radius_servers' needs to be defined for router of model
VPN3K. Each element must be a host.

- A network having id hosts must not be used in a rule.




Multiple instances if one host:id:&lt;name&gt; can get defined in
different networks of a topology. When referencing an id host, one has
to append the name of the enclosing newtork to make the reference
definite.  ` host:id:<name> ` is referenced as `
host:id:<name>.<network> `

####Special handling of access lists at VPN3K device

- First use all regular rules were destination is in one of the denied
  networks below. 
- Deny access to all networks, which talk to the vpn3k device, but
  which are not protected by some managed device; i.e.
  
  -  container network of id hosts,
  - network of remote office with unmanged VPN router
  - networks attached to the 'no_check' interface of the vpn3k device.
  
- Permit any traffic from IP address of remote host or network.


##Handling of 'any' objects {#handling_any}

The meaning of 'any' is different in a NetSPoC rule from that in an ACL.
For NetSPoC, any:X means "any network object of the security domain
where any:X is located".
For an ACL which filters incoming traffic of an interface, any
(i.e. 0.0.0.0/0.0.0.0) means "any network object beyond the interface
where the ACL is applied to".

as source:
: any data object connected directly or indirectly with
this interface.

as destination:
: any data object located behind the router where the
interface belongs to.

##PIX security levels

PIX firewalls have a security level associated with each interface.
We don't want to expand our syntax to state them explicitly,
but instead we try to derive the level from the interface name:

- Interface 'inside' gets level 100
- Interface 'outside' gets level 0
- For each other interface there must be a number at the end of its
name which is taken as the relative security level.  
I.e 'DMZ-slot:4' < 'DMZ-slot:5'

It is not necessary the find the exact level; what we need to know
is the relation of the security levels to each other.

##Redundant rules

NetSPoC automatically detects and eliminates

- duplicate elements in groups,
- duplicate rules and
- redundant rules.

Duplicate or redundant rules and elements should be avoided. If you
later remove one of two redundant rules, it will be at least
surprising that the traffic will still be permitted.


Per default, NetSPoC gives warnings for redundant rules and
elements. But the behavior can be adjusted by command line switches and
by attributes at service definitions.

- Use command line
switch `-check_duplicate_rules_=0|1|warn` to globally
enable or disable checks for duplicate rules.
- Use command line
switch `-check_redundant_rules_=0|1|warn` to globally
enable or disable checks for redundant rules.
- Add attribute `overlaps = service:<name>, ...;`
at a service definition with names of other services. If those other
services have rules that are duplicate or redundant compared to some
rules of current service, printing of warning / error messages is
disabled for this case.


##Unenforceable rules
Use command line switch `-check_unenforceable=0|1|warn` to control the behavior if NetSPoC detects unenforceable rules.

##Generated Code

- Access control lists
- Routing
- NAT commands for some devices


##Supported devices


- Linux 
 
  - iptables, ruleset is arranged into highly optimized tree of chains.
  - ip route
 

- ASA, PIX 

  - access-list
  - object-group
  - icmp, telnet, ssh, http
  - route

- Cisco IOS with firewall feature set
 
  - ip access-list extended
  - ip route
 
- Cisco IOS without firewall feature set
 
  - ip access-list extended (rules for answer packets are added automatically)
  - ip route
 


##Private configuration context

The configuration for NetSPoC is typically spread to multiple files
located inside a directory. For a large topology we might have
multiple administrators with responsibility for only part of the
topology. 


The concept of 'private' configuration contexts allows to partition
the configuration files into different areas of responsibility.  All
definitions inside a directory or a file named 'xxx.private' are
marked as private for 'xxx'. All other definitions stay public.
Private definitions have some restrictions to prevent inadvertent
changes from other parts of a large set of configuration files:

- A private network object (host, network, interface, any) may
only be referenced by private rules, groups, crypto definitions and
pathrestrictions of the same context.
- Only a private interface may be attached to a private network;
both must belong to the same private context.



![Two private contexts and public context](private-context.png)

##Changing default values of command line switches

The behavior of netspoc can be adjusted using command line switches. 
See <a href="netspoc.html">man netspoc</a> for details.


You can change values for command line switches permanently for a
project by adding a file named "config" in the toplevel directory of
the Netspoc configuration. 


Format of the "config" file:

- Assignment `key = value;`.  
  See <a href="netspoc.html">man netspoc</a> for valid keys / value pairs.
- Comment lines:  `# ...`


##Owners and admins


 Copyright (c) 2012, Heinz Knutzen 
<A HREF="mailto:heinzknutzen@users.berlios.de">heinzknutzen@users.berlios.de</A>

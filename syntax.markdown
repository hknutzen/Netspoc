---
layout: default
---

* Table of Content
{:toc}

# Netspoc Policy Language

##General syntax

`<name>` is built from one ore more alphanumerical utf8 characters together
with hyphen and underscore.  
`<external name>` is built from any characters, 
but not whitespace, no delimiters `;,=` and no quotes `"'`.  
`<string>` is like `<external name>`, but with space characters included.

`... *   `
: zero or more occurences

`.. | .. `
: alternatives

`[...]   `
: optional part

`(...)   `
: to clarify scope of * and |

`"[", "]"`
: real bracket characters

##Network definition

    <network definition> ::=
      network:<name>[/<bridge-part>] = {
         [ <description> ]
         ip = <ip-net>; | unnumbered;
         <network NAT> *
         [ subnet_of = network:<name>; ]
         [ has_subnets;                ]
         [ crosslink;                  ]
         [ isolated_ports;             ]
         [ owner = <name>;             ]
         <host definition> *
      }

    <network NAT> ::=
      nat:<name> = { 
         ip = <ip-net>; |  hidden; | identity;
         [ dynamic;                    ]
         [ subnet_of = network:<name>; ]
      }

    <bridge-part> ::= <name>
    <description> ::= description = <text_to_end_of_line>[;]
    <ip-net>      ::= <ip>/<prefix-len> | <ip>/<ip> | <ip>;mask=<ip>
    <ip>          ::= n.n.n.n with 0 <= n <= 255
    <prefix-len>  ::= 0 | 1 | 2 | ... | 32

##Host definition

    <host definition> ::=
      host:<name> = { 
         [ <description> ]
         ip = <ip>; | range = <ip>-<ip>;
         [ owner = <name>;            ]
         [ policy_distribution_point; ]
         <host NAT> *
         [ managed;                   ]
         [ model = Linux;             ]
         [ hardware = <external name>;]
      }

    <host NAT> ::= nat:<name> = { ip = <ip>; }

##Router definition

    <router definition> ::=
      router:<name>[@<VRF-name>] = {
         [ <description> ]
         [ managed; | managed = <filter type>;         ]
         [ model = <model>;                           ]
         [ filter_only = <ip-prefix>(, <ip-prefix>)*; ]
         [ routing = ( EIGRP | OSPF | manual );       ]
         [ no_group_code;    ]
         [ no_crypto_filter; ]
         [ std_in_acl;       ]
         [ log_deny;         ]
         [ owner = <name>;   ]
         <interface definition> *
         <short interface definition> *
      }
    
    <VRF-name>    ::= <name>
    <filter type> ::= primary | full | standard | secondary | local
    <model>       ::= Linux | ASA | ASA,8.4 | PIX | IOS | IOS,FW | NX-OS
    <ip-prefix>   ::= <ip>/<prefix-len>

##Interface definition

    <interface definition> ::= 
      interface:<name>[/<bridge-part>] = {
         [ <description> ]
         ip = ( <ip>(, <ip>)* | unnumbered | negotiated );
         <secondary interface definition> *
         [ <virtual interface definition>       ]
         <host NAT> *
         [ bind_nat = <name>(, <name>)*;        ]
         [ dhcp_server;                         ]
         [ disabled;                            ]
         [ hardware = <external name>;          ]
         [ loopback;                            ]
         [ no_in_acl;                           ]
         [ promiscuous_port;                    ]
         [ reroute_permit = <object set>;       ]
         [ routing = ( EIGRP | OSPF | manual ); ]
         [ security_level = <int>;              ]
         [ subnet_of = network:<name>;          ]
      }

here `<object set>` must expand to networks.

    <secondary interface definition> ::=
      secondary:<name> = { ip = <ip>; }

    <virtual interface definition> ::=
      virtual = { 
           ip = <ip>;
           [ type = ( VRRP | HSRP | HSRPv2 ); ]
           [ id = <int>;             ]
      }

    <short interface definition> ::=
      interface:<name>;

## Aggregate definition

    <aggregate defintion> ::=
      any:<name> = { 
         [ <description> ]
         link = ( network:<name> | router:<name> ); 
         [ ip = <ip-net>;     ]
         [ owner = <name>;    ]
         [ has_unenforceable; ]
         [ no_in_acl;         ]
      }

## Area definition

    <area definition> ::=
      area:<name> = {
         [ <description> ]
         border = <object set>; | anchor = network:<name>;
         [ auto_border;    ]
         [ owner = <name>; ]
         <network NAT> *
         [ <default router attributes> ]
      }

    <default router attributes> ::= 
      router_attributes = {
        [ owner = <name>; ]
      }

where `<network NAT>` must be hidden or dynamic.

##Set of objects

    <object set>   ::= <intersection> | <object set>,<intersection>
    <intersection> ::= <complement> | <intersection>&<complement>
    <complement>   ::= <network object> | !<network object>

    <network object> ::=
      host:<name> | network:<name> | any:<name> | interface:<name>.<name>[.<name>] 
      | group:<name> | <auto group>


##Automatic group

    <auto group> ::=
      interface:<name>."["<selector>"]"
    | interface:"[" [ managed & ] <object set with area>"]"."["<selector>"]"
    | network:"["<object set with area>"]"
    | any:"[" [ ip = <ip-net> & ] <object set with area>"]"
    | host:"["<object set with area>"]"

    <selector> ::= auto | all
    <object set with area> is like <object set> 
      but with additional area:<name> allowed in <network object>


##Group definition

    <group definition> ::=
      group:<name> = <object set>;


##Protocol definition

    <protocol definition> ::=
      protocol:<name> = <simple protocol>|<modified protocol>;

    <simple protocol> ::= 
      ip 
    | tcp [[<range> :] <range>]
    | udp [[<range> :] <range>]
    | icmp [<int>[/<int>]]
    | proto <int> 

    <range> ::= <int> | <int>-<int>

    <modified protocol> ::= <simple protocol> | <modified protocol>,<protocol modifier>

    <protocol modifier> ::= 
      stateless | oneway | reversed 
      | src_net | dst_net | src_any | dst_any
      | overlaps | no_check_supernet_rules

##Groups of protocols

    <protocol group definition> ::=
      protocolgroup:<name> = <protocol>(, <protocol>)*;

    <protocol> ::= protocol:<name> | protocolgroup:<name> | <simple protocol>


##Service definition

    <service definition> ::=
      service:<name> = {
         [ <description>              ]
         [ disabled;                  ]
         [ multi_owner;               ]
         [ unknown_owner;             ]
         [ sub_owner = <name>;        ]
         [ has_unenforceable;         ]
         [ overlaps = service:<name>(, service:<name>)*; ]
         user = [ foreach ] <object set>;
         <rule> * 
      }

with

    <rule> ::=
      permit|deny 
            src = <object set with 'user'>;
            dst = <object set with 'user'>;
            prt = <protocol>(,<protocol>)*;
      <object set with 'user'> is like <object set> 
       but with additional keyword 'user' allowed in <network object>

##Global permit

    <global permit> ::=
      global:permit = <protocol>(, <protocol>)*;

##Path restriction

    pathrestriction:<name> = 
      [ <description> ]
      <object set> 
    ;

where `<object set>` must expand to interfaces.

##Owner definition

    owner:<name> = {
      [ alias = <string>; ]
      admins = <email>(, <email>)*;
      [ watchers = <email>(, <email>)*; ]
      [ extend;      ]
      [ extend_only; ]
      [ show_all;    ]
    }
    
    <email> ::= some valid email address or 'guest'

##Encryption

###Crypto definition

    crypto:<name> = { 
      [ <description> ]
      type = ipsec:<name>;
      tunnel_all;
      [ detailed_crypto_acl; ]
    }

    ipsec:<name> = {
       key_exchange = isakmp:<name>;
       esp_encryption = ( aes | aes192 | aes256 | des | 3des | none );
       esp_authentication = ( md5_hmac | sha_hmac | none );
       ah = ( md5_hmac | sha_hmac | none );
       pfs_group = ( 1 | 2 | 5 | none );
       lifetime = <number> <timeunit>;
    }

    isakmp:<name> = {
       identity = ( address | fqdn );
       nat_traversal = ( on | additional | off );
       authentication = ( preshare | rsasig );
       encryption = ( aes | aes192 | aes256 | des | 3des );
       hash = ( md5 | sha );
       group = ( 1 | 2 | 5 );
       lifetime = <number> <timeunit>;
    }

with

    <timeunit> ::= sec | min | hour | day | secs | mins | hours | days

### Tunnel definition

    interface:<name1> = {
      ..
      hub = crypto:<name>(,crypto:<name>)*;
      [ no_check; ]
    }

    interface:<name2> = {
      ..
      spoke = crypto:<name>;
    }

Crypto is supported for model 'ASA' and 'IOS'.

Model `ASA,VPN` switches to VPN concentrator mode. Default is site-to-site mode.

Model `IOS,EZVPN` generates EasyVPN configuration for 
IOS router connected to VPN concentrator.

Additional attributes need to be defined for model `ASA,VPN` 
in attribute `radius_attributes`.

    router:<name> = {
      ..
      <radius-attributes>
      ..
    }

    <radius-attributes> ::=
      radius_attributes = {
        trust-point = <string>;
        [ banner = <string>;                      ]
        [ dns-server = <string>;                  ]
        [ default-domain = <string>;              ]
        [ split-dns;                              ]
        [ wins-server = <string>;                 ]
        [ vpn-access-hours = <string>;            ]
        [ vpn-idle-timeout = <string>;            ]
        [ vpn-session-timeout = <string>;         ]
        [ vpn-simultaneous-logins = <string>;     ]
        [ vlan = <string>;                        ]
        [ authentication-server-group = <string>; ]
        [ authorization-server-group = <string>;  ]
        [ authorization-required;                 ]
        [ username-from-certificate = <string>;   ]
      }

###Software client

    <Software client> ::=
      host:id:<cert-name> = { .. }
    <Software client group> ::=
      host:id:<cert-match> = { .. }

    <cert-name>  ::= <name>(.<name>)*@<name>.<name>(.<name>)*
    <cert-match> ::=                 @<name>.<name>(.<name>)*

Host definition of software client and correspondig network definition
can have `<radius-attributes>`, which augment or overwrite attributes
of correspondig VPN concentrator.

### Hardware client

    interface:<name> = {
      ..
      id = <cert-name>
      ..
    }



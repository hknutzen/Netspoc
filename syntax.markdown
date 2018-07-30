---
layout: default
---

<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

# Netspoc Policy Language
{:.no_toc}

## General syntax

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

## Definitions for IPv4 and IPv6

### In IPv4 mode

    <ip>           ::= n.n.n.n with 0 <= n <= 255
    <prefix-len>   ::= 0 | 1 | 2 | ... | 32

### In IPv6 mode

    <ip>           ::= some valid IPv6 address
    <prefix-len>   ::= 0 | 1 | 2 | ... | 128

## Netspoc configuration

    <netspoc configuration> ::=
    (
      <network definition>
    | <router definition>
    | <aggregate defintion>
    | <area definition>
    | <group definition>
    | <protocol definition>
    | <protocol group definition>
    | <service definition>
    | <pathrestriction definition>
    | <owner definition>
    | <crypto definition>
    | <ipsec definition>
    | <isakmp definition>
    )*


## Network definition

    <network definition> ::=
      network:<network name> = {
         [ <description> ]
         ip = <ip-net>; | unnumbered;
         <network NAT> *
         [ subnet_of = network:<network name>; ]
         [ has_subnets;                ]
         [ crosslink;                  ]
         [ owner = <name>;             ]
         [ partition = <name>;         ]
         <host definition> *
      }

    <network NAT> ::=
      nat:<name> = {
         ip = <ip-net>; |  hidden; | identity;
         [ dynamic;                    ]
         [ subnet_of = network:<network name>; ]
      }

    <network name> ::= <name>[/<bridge-part>]
    <bridge-part>  ::= <name>
    <description>  ::= description = <text_to_end_of_line>[;]
    <ip-net>       ::= <ip>/<prefix-len>

## Host definition

    <host definition> ::=
      host:<name> = {
         [ <description> ]
         ip = <ip>; | range = <ip>-<ip>;
         [ owner = <name>;            ]
         <host NAT> *
         [ managed;                   ]
         [ model = Linux;             ]
         [ server_name = <name>;      ]
         [ hardware = <external name>;]
      }

    <host NAT> ::= nat:<name> = { ip = <ip>; }

## Router definition

    <router definition> ::=
      router:<router name> = {
         [ <description> ]
         [ managed; | managed = <filter type>;        ]
         [ model = <model>;                           ]
         [ filter_only = <ip-net>(, <ip-net>)*; ]
         [ routing = ( EIGRP | OSPF | dynamic | manual ); ]
         [ policy_distribution_point = host:<name>;   ]
         [ general_permit = <protocol list>;          ]
         ( log:<name> [= (<ASA-modifier> | <IOS-modifier>)]; )*
         [ acl_use_real_ip;  ]
         [ no_group_code;    ]
         [ no_protect_self;  ]
         [ log_deny;         ]
         [ owner = <name>;   ]
         <interface definition> *
         <short interface definition> *
      }

    <router name>  ::= <name>[@<VRF-name>]
    <VRF-name>     ::= <name>
    <filter type>  ::= primary | full | standard | secondary | local |
                       routing_only
    <model>        ::= Linux | ASA | IOS | IOS,FW | NX-OS
    <ASA-modifier> ::= alerts | critical | debugging | disable | emergencies |
                       errors | informational | notifications | warnings
    <IOS-modifier> ::= log-input

## Interface definition

    <interface definition> ::=
      interface:<network name> = {
         [ <description> ]
         [ ip = ( <ip>(, <ip>)* | unnumbered | negotiated ); ]
         <secondary interface definition> *
         [ <virtual interface definition>       ]
         (<host NAT> | <network NAT>)*
         [ bind_nat = <name>(, <name>)*;        ]
         [ dhcp_client;                         ]
         [ dhcp_server;                         ]
         [ disabled;                            ]
         [ hardware = <external name>;          ]
         [ loopback;                            ]
         [ no_in_acl;                           ]
         [ reroute_permit = <object set>;       ]
         [ routing = ( EIGRP | OSPF | dynamic ); ]
         [ subnet_of = network:<network name>;          ]
         [ vip;                                 ]
         [ owner = <name>;                      ]
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
      interface:<network name>;

## Aggregate definition

    <aggregate defintion> ::=
      any:<name> = {
         [ <description> ]
         link = network:<network name>;
         [ ip = <ip-net>;           ]
         [ owner = <name>;          ]
         <network NAT> *
         [ has_unenforceable;       ]
         [ no_check_supernet_rules; ]
      }

## Area definition

    <area definition> ::=
      area:<name> = {
         [ <description> ]
         ( [ border = <object set>; ]
           [ inclusive_border = <object set>; ]
         ) | anchor = network:<network name>;
         [ auto_border;    ]
         [ owner = <name>; ]
         <network NAT> *
         [ <default router attributes> ]
      }

    <default router attributes> ::=
      router_attributes = {
        [ owner = <name>; ]
        [ policy_distribution_point = host:<name>; ]
        [ general_permit = <protocol list>;        ]
      }

where `<network NAT>` must be hidden or dynamic.

## Set of objects

    <object set>   ::= <intersection> | <object set> , <intersection>
    <intersection> ::= <network object> | <intersection> & <complement>
                                        | <complement> & <intersection>
    <complement>   ::= <network object> | ! <network object>

    <network object> ::= host:<name>
                       | network:<network name>
                       | any:<name>
                       | interface:<router name>.<network name>[.<name>]
                       | group:<name>
                       | <auto group>

## Automatic group

    <auto group> ::=
      interface:<router name>."["<selector>"]"
    | interface:"[" [ managed & ] <object set with area>"]"."["<selector>"]"
    | network:"["<object set with area>"]"
    | any:"[" [ ip = <ip-net> & ] <object set with area>"]"
    | host:"[" [ managed & ] <object set with area>"]"

    <selector> ::= auto | all
    <object set with area> is like <object set>
      but with additional area:<name> allowed in <network object>


## Group definition

    <group definition> ::=
      group:<name> =
        [ <description> ]
        <object set>
      ;


## Protocol definition

    <protocol definition> ::=
      protocol:<name> = <simple protocol>|<modified protocol>;

    <simple protocol> ::=
      ip
    | tcp [[<range> :] <range>]
    | udp [[<range> :] <range>]
    | icmp   [<int>[/<int>]]			(in IPv4 mode)
    | icmpv6 [<int>[/<int>]]			(in IPv6 mode)
    | proto <int>

    <range> ::= <int> | <int>-<int>

    <modified protocol> ::= <simple protocol> | <modified protocol>,<protocol modifier>

    <protocol modifier> ::=
      stateless | oneway | reversed
      | src_net | dst_net
      | overlaps | no_check_supernet_rules

## Groups of protocols

    <protocol group definition> ::=
      protocolgroup:<name> = <protocol list>;

    <protocol list> ::= <protocol>(, <protocol>)*
    <protocol> ::= protocol:<name> | protocolgroup:<name> | <simple protocol>


## Service definition

    <service definition> ::=
      service:<name> = {
         [ <description>              ]
         [ disable_at = <date>;       ]
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
            prt = <protocol list>;
          [ log = <name>(, <name>)*; ]

      <object set with 'user'> is like <object set>
       but with additional keyword 'user' allowed in <network object>

      <date> ::= a date with format YYYY-MM-DD

## Path restriction

    <pathrestriction definition> ::=
      pathrestriction:<name> =
        [ <description> ]
        <object set>
      ;

where `<object set>` must expand to interfaces.

## Owner definition

    <owner definition> ::=
      owner:<name> = {
        admins = <email>(, <email>)*;
        [ watchers = <owner_email_wildcard>(, <owner_email_wildcard>)*; ]
        [ extend;           ]
        [ extend_only;      ]
        [ extend_unbounded; ]
        [ show_all;         ]
      }

    <email> ::= some valid email address or 'guest'
    <domain> ::= some valid email domain part
    <wildcard> ::= "["all"]"@<domain>
    <owner_email_wildcard> ::= <email> | owner:<name> | <wildcard>

`admins` are optional if `extend_only` is set.

## Encryption

### Crypto definition

    <crypto definition> ::=
      crypto:<name> = {
        [ <description> ]
        type = ipsec:<name>;
        [ detailed_crypto_acl; ]
      }

    <ipsec definition> ::=
      ipsec:<name> = {
         key_exchange = isakmp:<name>;
         esp_encryption = ( aes | aes192 | aes256 | des | 3des | none );
         esp_authentication = ( md5 | sha | sha256 | sha384 | sha512 | none );
         ah = ( md5 | sha |sha256 | sha384 | sha512 | none );
         pfs_group = ( 1 | 2 | 5 | 14 | 15 | 16 | 19 | 20 | 21 | 24 | none );
         lifetime = [ <int> <timeunit> ] [ <int> kilobytes ];
      }

    <isakmp definition> ::=
      isakmp:<name> = {
         ike_version = ( 1 | 2 );
         identity = ( address | fqdn );
         nat_traversal = ( on | additional | off );
         authentication = ( preshare | rsasig );
         encryption = ( aes | aes192 | aes256 | des | 3des );
         hash = ( md5 | sha | sha256 | sha384 | sha512 );
         group = ( 1 | 2 | 5 | 14 | 15 | 16 | 19 | 20 | 21 | 24 );
         lifetime = <int> <timeunit>;
         trust_point = <name>;
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

Additional attributes need to be defined for model `ASA,VPN` in
attribute `radius_attributes`. These attributes are used at host
definitions of software clients, but are also inherited from
correspondig network and VPN router definition.

    host:id:<cert-name>  = { .. <radius-attributes> .. }
    host:id:<cert-match> = { .. <radius-attributes> .. }
    network:<name>       = { .. <radius-attributes> .. }
    router:<name>        = { .. <radius-attributes> .. }

    <radius-attributes> ::=
      radius_attributes = {
        trust-point = <string>;
        [ banner = <string>;                      ]
        [ check-subject-name = <string>;          ]
        [ check-extended-key-usage = <string>;    ]
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
        [ split-tunnel-policy = tunnelall | tunnelspecified; ]
      }

### Software client

Software clients are similar to hosts, but special names are used.

    network:<network name> = {
      ..
      <Software client>*
      <Software client group>*
      ..
    }

    <Software client> ::=
      host:id:<cert-name> = { .. }
    <Software client group> ::=
      host:id:<cert-match> = { .. }

    <cert-name>  ::= <name>(.<name>)*@<name>.<name>(.<name>)*
    <cert-match> ::=                 [@]<name>.<name>(.<name>)*

Host definition of software client and correspondig network definition
can have `<radius-attributes>`, which augment or overwrite attributes
of correspondig VPN concentrator.

### Hardware client

    interface:<name> = {
      ..
      id = <cert-name>;
      ..
    }

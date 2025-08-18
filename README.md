Netspoc
=======

A network security policy compiler.

[![Test Status](https://github.com/hknutzen/Netspoc/workflows/tests/badge.svg)](https://github.com/hknutzen/Netspoc/actions?query=workflow%3A"tests")
[![Coverage Status](https://coveralls.io/repos/github/hknutzen/Netspoc/badge.svg?branch=master)](https://coveralls.io/github/hknutzen/Netspoc?branch=master)

Netspoc is free software to manage all the packet filter devices inside your network topology. Filter rules for each device are generated from one central ruleset, using a description of your network topology.

- Supports different types of devices
  - Linux iptables
  - Cisco  ASA, IOS
  - Palo-Alto firewalls
  - VMWare NSX tier 0 and tier 1 gateways
- Rules are optimized globally
  - Adjacent IP ranges and port ranges are joined.
  - Redundant rules are removed and optionally warned about.
- Highly optimized chains for iptables are generated.
- Object-groups for ASA, PAN-OS and NSX are generated.
- IPSec configuration for Cisco ASA and IOS is generated.
- Commands for static routing are generated (optionally).
- Network address translation (NAT) is supported.
- Powerful rules language
   - Groups can be defined and reused in different rules.
   - Automatic groups utilize relationships of the topology.
- Allows to define a secondary packet filter which gets simpler rules
  if a data stream has already been filtered at some other device.
- Complex topologies with redundant paths are supported.
- Pathrestrictions allow to restrict paths inside a redundant topology.

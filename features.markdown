---
layout: default
---

# Features

- Supports different devices
  - Linux chains for iptables.
  - Access lists for ASA.
  - Access lists for IOS with and without Firewall Feature Set.
  - Palo-Alto PAN-OS.
  - VMWare NSX Tier-0 & Tier-1 gateways.
- Supports IPv4 and IPv6
  - Allows to define dual stack objects, having both an IPv4 and IPv6 address.
  - Rules between dual stack objects generate ACLs for IPv4 and IPv6.
- Rules are optimized globally
  - Adjacent IP ranges and port ranges are joined.
  - Redundant rules are removed and optionally warned about.
- Highly optimized chains for iptables are generated.
- Object-groups for ASA and NX-OS are generated.
- IPSec configuration for Cisco ASA and IOS is generated.
- Commands for static routing are generated (optionally).
- Network address translation (NAT) is supported.
- HSRP / VRRP clusters are supported.
- Multicast traffic for OSPF, EIGRP, HSRP, VRRP is supported.
- Powerful rules language
   - Groups can be defined and reused in different rules.
   - Automatic groups utilize relationships of the topology.
- Allows to define a secondary packet filter which gets simpler rules
  if a data stream has already been filtered at some other device.
- Complex topologies with redundant paths are supported.
- Pathrestrictions allow to restrict paths inside a redundant topology.
- This software has been tested to run on Linux.

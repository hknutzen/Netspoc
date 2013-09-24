Netspoc
=======

A network security policy compiler. 

Netspoc is free software to manage all the packet filter devices inside your network topology. Filter rules for each device are generated from one central ruleset, using a description of your network topology.

- Supports Cisco and Linux devices
  - Chains for iptables.
  - Access lists for ASA, PIX, NX-OS
  - Access lists for IOS with and without Firewall Feature Set.
- Rules are optimized globally 
  - Adjacent IP ranges and port ranges are joined.
  - Redundant rules are removed and optionally warned about.
- Highly optimized chains for iptables are generated.
- Object-groups for ASA, PIX and NX-OS are generated.
- IPSec configuration for Cisco ASA, ASA v8.4 and IOS is generated.
- Commands for static routing are generated (optionally).
- Network address translation (NAT) is supported.
- NAT configuration for Cisco ASA and ASA v8.4 is generated.
- HSRP / VRRP clusters are supported.
- Multicast traffic for OSPF, EIGRP, HSRP, VRRP is supported.
- Powerful rules language 
   - Groups can be defined and reused in different rules.
   - Automatic groups utilize relationships of the topology.
- Allows to define a secondary packet filter which gets simpler rules 
  if a data stream has already been filtered at some other device.
- Complex topologies with redundant paths are supported.
- Pathrestrictions allow to restrict paths inside a redundant topology.
- Supports network with isolated ports where traffic is entered and exited 
  at the same interface of the packet filter.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Program "format-netspoc" now sorts IPv6 hosts by address.

## [2025-07-22-1444]

### Removed

- Attribute 'bind_nat' is no longer valid.
  Use 'nat_out' instead.

### Changed

- No longer superflously create zones from nat_in.
- Attribute 'has_subnets' is ignored at IPv6 part of dual stack object.
  But 'has_subnets' is still applied to both parts of network
  if both addresses have /0 address.
- A warn message is shown on useless attribute 'has_subnets'.
- A warn message is shown on useless attribute 'subnet_of'
  at NAT definition of network.

### Fixed

- Better warn message for empty IPv6 area from dual stack area.
- Better warn message for IPv6 subnet of dual stack object.
  It is no longer proposed to add 'subnet_of',
  but to split the network into separate IPv4 and IPv6 objects.
- No longer show error message
  'Must not use only IPv6 / IPv4 part of dual stack object',
  if supernet of missing network is still applied.
- Program "cut-netspoc" now works with dual-stack topology.

## [2025-05-26-1321]

### Fixed

- Fixed attribute 'nat_in'.
  Previously it was only applied to the first suitable interface
  and hence only usable at router with two interfaces.

## [2025-05-20-1401]

### Removed

- Attribute 'radius_attributes' is no longer valid.
  Use 'vpn_attributes' instead.

### Changed

- Changed name of attribute 'bind_nat' to 'nat_out'.
  This version supports both attributes.
  But support for 'bind_nat' will be removed in next version.

### Added

- Introduced new attribute 'nat_in' at interface of router.
  "nat_in = t1;" at an interface means:
  If packets enter this interface, then NAT defined by "nat:t1"
  is applied at each outgoing interface without "nat_in = t1;".
  See #23 for details.

### Fixed

- Fixed inversed inheritance at unnamed aggregate:
    - Contained unnamed aggregate is ignored.
    - Unnamed aggregate no longer inherits from enclosing unnamed aggregate.
- Fixed static route with sole virtual interface as next hop.
  Use IP of virtual interface instead of physical interface.
- No longer accidently split NAT domains. This fixes #22.

## [2025-04-17-1102]

### Changed

- Attribute 'radius_attributes' in Netspoc syntax has been renamed to
  'vpn_attributes'.
  This version supports both attributes.
  But support for 'radius_attributes' will be removed in next version.

### Added

- Support for vpn_attribute 'client-bypass-protocol' has been added.
  Example:
  "vpn_attributes = { client-bypass-protocol = enable; }"
  is added to group-policy as
  "client-bypass-protocol enable"

## [2025-04-14-1136]

### Changed

- No longer show warning on redundant owner at dual stack object
  if owner is inherited from pure IPv4 or pure IPv6 object.
- Attribute 'subnet_of' is ignored at IPv6 part of dual stack object.
- If attribute 'bind_nat' is given at pure IPv6 interface,
  this attribute is ignored and a warning is shown.

## [2025-04-09-1408]

### Changed

- It is no longer allowed to use only IPv4 part or only IPv6 part of
  dual stack objects in rules. When displaying such a partial rule in
  Netspoc-Web, it can't be distinguished from a complete rule.
- Attribute .cluster of a zone now has a dual stack zone as first element
  if this zone cluster has at least one dual stack zone.
- It is no longer valid to connect IPv4 zone to multiple IPv6 zones
  or vice versa if a non matching aggregate is defined at this zone
  which would match both, IPv4 and IPv6 addresses.

### Removed

- Attributes 'ipv4_only' and 'ipv6_only' are no longer valid at areas.
  This is needed to prevent creating partial rules.

### Fixed

- If owner is given at dual stack zone this owner is now correctly
  applied to IPv6 part of this zone.
- Processing error message for thousands of duplicate rules needed too
  much time, resulting in a seemingly stalled run of program
  'netspoc'. This has been fixed.
- Applied multiple fixes for named, non matching dual stack aggregates,
  e.g. any:a = { link = network:n; }
    - Fixed non determinism in export-netspoc.
      IPv4 and IPv6 adddresses are now always shown, if avalaible.
    - Dual stack property is no longer lost for copied aggregates
      in zone cluster.
- Applied multiple fixes for unnamed, non matching aggregates,
  e.g. any:[network:n]
    - If any:[ip=0.0.0.0/0 & network:n] is used in dual stack zone,
      this no longer implicitly adds an any:[ip6=::/0 & network:n].
    - Only if any:[network:n] is used in dual stack zone,
      this adds IPv4 and IPv6 aggregates.
    - any:[network:n] in dual stack zone must not be used
      in pure IPv4 or IPv6 rule.
      Use any:[ip=0.0.0.0/0 & network:n]
      or any:[ip6=::/0 & network:n] instead.

## [2025-03-18-1556]

### Added

- 'CHANGELOG.md'
  Newest entries are used to maintain github releases page.
- 'nfpm.yaml'
  configures program 'nfpm' to build 'rpm' + 'deb' packages.

### Changed

- Current date and time is used as version number.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

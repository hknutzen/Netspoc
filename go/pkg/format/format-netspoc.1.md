# format-netspoc 1 "" Netspoc "User Manual"

# NAME

format-netspoc - Format Netspoc configuration files

# SYNOPSIS

format-netspoc [options] netspoc-data

# DESCRIPTION

format-netspoc reads each file of a Netspoc configuration
and prints back modified content:

- indent lines correctly
- sort lists by IP address:
  - hosts of networks,
  - successive router interfaces having attribute `vip`.
- sort lists of Netspoc objects in groups
  and behind `user=`, `src=`, `dst=` of rules:
  - by type (group < area < any < network < interface < host)
  - by IP address, if given as part of name (e.g. "host:abc-10_1_2_3")
  - by name
- lists of protocols in protocolgroups and behind `prt=` of rules
  are sorted
  - named protocols
    - by type (protocolgroup < protocol)
    - by name
  - simple, unnnamed protocols
    - by protocol (icmp < ip < proto < tcp < udp)
    - by port, icmp type/code or by protocol number
- sort value lists of attributes of all toplevel definitions case insensitively
- sort attributes of service by name

# OPTIONS

**-q**, **--quiet**
:   Don't show changed files.

**-h**, **--help**
:   Print a brief help message and exit.

# COPYRIGHT AND DISCLAIMER

(c) 2025 by Heinz Knutzen, heinz.knutzen@googlemail.com

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

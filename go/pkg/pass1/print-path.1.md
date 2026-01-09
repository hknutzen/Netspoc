# print-path 1 "" Netspoc "User Manual"

# NAME

print-path - Print path between two objects in the network topology

# SYNOPSIS

print-path [options] FILE|DIR SOURCE DESTINATION

# DESCRIPTION

This program reads a Netspoc configuration and finds the path between
two network objects (SOURCE and DESTINATION). It analyzes the routing
and outputs all network elements (networks and routers) that are part
of the path as a JSON array to **standard output (STDOUT)**.

The program determines which networks and routers would be traversed
when packets flow from the source to the destination, taking into account
the network topology and routing configuration.

Both SOURCE and DESTINATION can be:

- Network names (e.g., `network:n1`)
- Host names (e.g., `host:h1`)
- Interface names (e.g., `interface:r1.n1`)

The output is a sorted JSON array containing the names of all
networks, routers, and other elements along the path.

# OPTIONS

**-q**, **--quiet**
:   Don't print progress messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Find path from network:n1 to network:n2 in Netspoc configuration:

`print-path netspoc/ network:n1 network:n2`

Find path from host:h1 to host:h2:

`print-path netspoc/ host:h1 host:h2`

Find path quietly without progress messages:

`print-path -q netspoc/ network:n1 network:n2`

# OUTPUT FORMAT

The output is a JSON array of strings, where each string is the name
of a network element (network or router) that is part of the path
from source to destination.

Example output:

`["network:n1", "network:n2", "router:r1"]`

# COPYRIGHT AND DISCLAIMER

(c) 2025 by Dominik Kunkel, netspoc@drachionix.eu

(c) 2025 by Heinz Knutzen, heinz.knutzen@googlemail.com

This program is part of Netspoc, a Network Security Policy Compiler.
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
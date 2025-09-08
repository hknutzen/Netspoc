# cut-netspoc 1 "" Netspoc "User Manual"

# NAME

cut-netspoc - Print parts of a netspoc configuration to STDOUT

# SYNOPSIS

cut-netspoc [options] netspoc-data [service:name ...]

# DESCRIPTION

cut-netspoc reads a Netspoc configuration
and prints parts of this configuration to STDOUT.
If one or more services are given as argument,
only those parts are printed, that are referenced by given services.
If no service is given, it acts as if all services are specified.
This is useful to eliminate unreferenced parts of the topology.

# OPTIONS

**-q**, **--quiet**
:   Don't print progress messages.

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

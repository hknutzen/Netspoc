# rename-netspoc 1 "" Netspoc "User Manual"

# NAME

rename-netspoc - Rename one or more objects in netspoc files

# SYNOPSIS

rename-netspoc [options] FILE|DIR SUBSTITUTION ...

# DESCRIPTION

This program reads a netspoc configuration and one or more
SUBSTITUTIONS. It substitutes found objects with its replacement in
each file. Changes are done in place, no backup files are created. But
only changed files are touched.

## SUBSTITUTION

A SUBSTITUTION is a pair of typed names "type:NAME1 type:NAME2".
NAME1 is searched and replaced by NAME2. Both types of a single
SUBSTITUTION must use the same type.
Multiple SUBSTITUTIONS can be applied in a single run of rename-netspoc.

A typed name can use any valid type and name in netspoc syntax.
Valid types are: `router network host any group area service owner
protocol protocolgroup pathrestriction nat isakmp ipsec crypto`.

A SUBSTITUTION of type `network` also changes `interface`s and `host:id`
which reference the given network.

A SUBSTITUTION of type `router` also changes `interface`s
which reference the given router.

A SUBSTITUTION of type `nat` also changes the corresponding
`nat_in` and `nat_out` lists.

# OPTIONS

**-f**, **--file** file
:   Read SUBSTITUTIONS from file.

**-q**, **--quiet**
:   Don't print status messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Rename `network:x` to `network:y` of Netspoc configuration in
directory `netspoc/`.
This also changes interface names referencing `network:x`,
e.g. `interface:r.x` is renamed to `interface:r.y` .

`rename-netspoc netspoc/ network:x network:y`

# COPYRIGHT AND DISCLAIMER

(c) 2025 by Heinz Knutzen, heinz.knutzen@googlemail.com

This program is part of Netspoc, a Network Security Policy Compiler.
http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

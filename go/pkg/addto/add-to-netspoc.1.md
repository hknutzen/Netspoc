# add-to-netspoc 1 "" Netspoc "User Manual"

# NAME

add-to-netspoc - Augment one or more objects in netspoc files

# SYNOPSIS

add-to-netspoc [options] FILE|DIR PAIR ...

# DESCRIPTION

This program reads a netspoc configuration and one or more
PAIRS of object names.
It augments first object by specified second object in
each file. Changes are done in place, no backup files are created. But
only changed files are touched.

## PAIR

A PAIR is a tuple of typed names "type1:NAME1" "type2:NAME2".
Occurences of "type1:NAME1" are searched and
replaced by "type1:NAME1, type2:NAME2".
Changes are applied only in group definitions and
in implicit groups inside rules, i.e. after `user =`, `src =`, `dst =`.
Multiple PAIRS can be applied in a single run of add-to-netspoc.

The following types can be used in PAIRS:
`network host interface any group area`.

# OPTIONS

**-f**, **--file** file
:   Read PAIRS from file.

**-q**, **--quiet**
:   Don't print status messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Add `network:y` at every occurrence of `network:x` in groups and rules
of Netspoc configuration in directory `netspoc/`:

`add-to-netspoc netspoc/ network:x network:y`

Add `host:y` at every occurrence of `group:g` and of `network:x`:

`add-to-netspoc netspoc/ group:g host:y network:x host:y`

Same, but read pairs from file:

`echo 'group:g host:y network:x host:y' > file;
 add-to-netspoc -f file netspoc/`

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
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

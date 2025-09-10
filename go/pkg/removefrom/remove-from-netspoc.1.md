# remove-from-netspoc 1 "" Netspoc "User Manual"

# NAME

remove-from-netspoc - Remove one or more objects from netspoc files

# SYNOPSIS

remove-from-netspoc [options] FILE|DIR OBJECT ...

# DESCRIPTION

This program reads a netspoc configuration and one or more OBJECTS. It
removes specified objects in each file. Changes are done in place, no
backup files are created. But only changed files are touched.

## OBJECT

An OBJECT is a typed name "type:NAME". Occurrences of
"type:NAME" are removed. Changes are applied only in group
definitions and in implicit groups inside rules, i.e. after `user =`,
`src =`, `dst = `.  Multiple OBJECTS can be removed in a single run of
remove-from-netspoc.

If a service gets empty `user`,`src` or `dst` after removal of OBJECT,
the definition of this service is removed as well.

If the to be removed object is a group, the definition of this group is
removed as well.

The following types can be used in OBJECTS:
`network host interface any group area`.

# OPTIONS

**-d**, **--delete**
:   Also delete the definition of host or unmanaged interface having
    attribute `loopback` or `vip`.

**-f**, **--file** file
:   Read OBJECTS from file.

**-q**, **--quiet**
:   Don't print status messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Remove occurrences of `network:x` in groups and rules
of Netspoc configuration in directory `netspoc/`:

`remove-from-netspoc netspoc/ network:x`

Remove `host:a`, `host:b` and `interface:r.x`.

`remove-from-netspoc netspoc/ host:a host:b interface:r.x`

Same, but read to be removed objects from file:

`echo 'host:a host:b interface:r.x > file;
 remove-from-netspoc -f file netspoc/`

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

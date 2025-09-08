# print-group 1 "" Netspoc "User Manual"

# NAME

print-group - Show elements of a netspoc group definition

# SYNOPSIS

print-group [options] FILE|DIR "group:name,..."

# DESCRIPTION

This program prints the elements of a Netspoc group.
It reads a group name from command line
and by default, shows a line with IP/prefixlen and name for each element.

Group is a named group, some automatic group, some named object or
a union or intersection or complement of simpler objects.

IP, name and additional columns are separated by TAB character.

Name and IP address of a dual stack object is shown as two lines:

- first line with IPv4 address and name,
- second line with IPv6 address and same name.

# OPTIONS

**-n**, **--name**
:   Show only name of elements.

**-i**, **--ip**
:   Show only IP address of elements.

**-o**, **--owner**
:   Show owner of elements in additional column.

**-a**, **-admins**
:   Show admins of elements as comma separated list in additional column.

**-u**, **--unused**
:   Show only elements not used in any rules.

**--nat** name
:   Uses network:name as reference when resolving IP address in a NAT environment.

**-q**, **--quiet**
:   Don't print progress messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Show names of elements of group:g
of Netspoc configuration in directory `netspoc/`:

`print-group --name netspoc/ group:g`

Show names and owners of elements of group:a without elements of group:b:

`print-group --name --owner netspoc/ 'group:a &! group:b'`

Show IP addresses of all hosts inside area:x:

`print-group --ip netspoc/ 'host:[area:x]'`

Show IP address and name of IPv6 networks inside area:x:

`print-group netspoc/ 'network:[any:[ip6=::/0 & area:x]]'`

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
*/

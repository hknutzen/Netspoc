# print-service 1 "" Netspoc "User Manual"

# NAME

print-service - Show rules of netspoc service definitions

# SYNOPSIS

print-service [options] FILE|DIR [SERVICE-NAME ...]

# DESCRIPTION

This program prints expanded rules of given Netspoc service definitions.
If no service name is given, all services are printed.

Output format is

with option `-i` (default):
:   `service-name:permit|deny src-ip dst-ip protocol-description`

with option `-n`:
:   `service-name:permit|deny src-name dst-name protocol-description`

with option `-i -n`:
:   `service-name:permit|deny src-ip src-name dst-ip dst-name protocol-description`

# OPTIONS

**-n**, **--name**
:   Show name of elements.

**-i**, **--ip**
:   Show IP address of elements.

**--nat** name
:   Uses network:name as reference when resolving IP address in a NAT environment.

**-q**, **--quiet**
:   Don't print progress messages.

**-h**, **--help**
:   Print a brief help message and exit.

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

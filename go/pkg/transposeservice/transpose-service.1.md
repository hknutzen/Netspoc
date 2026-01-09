# transpose-service 1 "" Netspoc "User Manual"

# NAME

transpose-service - Transpose source and destination in service definitions

# SYNOPSIS

transpose-service [options] FILE|DIR [service:]NAME ...

# DESCRIPTION

This program reads a Netspoc configuration and one or more SERVICE name(s).
It transposes the specified services in each file by switching the `user`
keyword between `src` and `dst` attributes in service rules. The
functionality of the service is not changed - the traffic flow remains
the same, only the perspective (which side is considered the `user`) 
is reversed.

For example, if a service has `user = src` and allows traffic from
network A to network B, after transposition it will have `user = dst`
and still allow the same traffic from network A to network B, but now
the destination (network B) is considered the `user` instead of the source.

Changes are done in place, no backup files are created. But only
changed files are touched.

Service names can be specified with or without the `service:` prefix.

## Limitations

A service can only be transposed if:

- It does not use the `foreach` keyword
- It has exactly one rule (not zero, not multiple)
- The rule has both `src` and `dst` attributes defined

# OPTIONS

**-f**, **--file** file
:   Read SERVICE names from file.

**-q**, **--quiet**
:   Don't show changed files.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Transpose service:s1 in Netspoc configuration in directory `netspoc/`:

`transpose-service netspoc/ service:s1`

This would change a service like:

    service:s1 = {
     user = network:n1;
     permit src = user; dst = network:n2; prt = tcp 80;
    }

to:

    service:s1 = {
     user = network:n2;
     permit src = network:n1; dst = user; prt = tcp 80;
    }

Transpose multiple services:

`transpose-service netspoc/ service:s1 service:s2`

Transpose services specified in a file:

`echo 'service:s1 service:s2' > services.txt;
 transpose-service -f services.txt netspoc/`

# COPYRIGHT AND DISCLAIMER

(c) 2025 by Dominik Kunkel, netspoc@drachionix.eu

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
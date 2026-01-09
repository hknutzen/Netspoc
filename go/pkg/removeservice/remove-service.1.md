# remove-service 1 "" Netspoc "User Manual"

# NAME

remove-service - Remove one or more services from netspoc files

# SYNOPSIS

remove-service [options] FILE|DIR [service:]NAME ...

# DESCRIPTION

This program reads a Netspoc configuration and one or more SERVICE names.
It removes specified services from each file. Changes are done in place, no
backup files are created. But only changed files are touched.

Service names can be specified with or without the `service:` prefix.
When a service is removed, its complete definition is deleted from
the configuration files.

Multiple services can be removed in a single run of remove-service.

# OPTIONS

**-f**, **--file** file
:   Read SERVICE names from file.

**-q**, **--quiet**
:   Don't show changed files.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

Remove service:s1 from Netspoc configuration in directory `netspoc/`:

`remove-service netspoc/ service:s1`

Remove multiple services:

`remove-service netspoc/ service:s1 service:s2 service:s3`

Remove services specified in a file:

`echo 'service:s1 service:s2' > services.txt;
 remove-service -f services.txt netspoc/`

Remove service quietly without showing changed files:

`remove-service -q netspoc/ service:s1`

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
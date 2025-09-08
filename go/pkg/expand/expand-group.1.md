# expand-group 1 "" Netspoc "User Manual"

# NAME

expand-group - Substitute group reference by its elements

# SYNOPSIS

expand-group [options] FILE|DIR GROUP-NAME ...

# DESCRIPTION

This program reads a Netspoc configuration and one or more
GROUP-NAMES. It substitutes specified group references in each file
and removes the corresponding group-definition. Each group reference
is substituted by elements of corresponding group definition.
GROUP-NAME is given with type as "group:NAME". Substitution occurs
textual, groups in groups are not expanded. Groups referenced in
intersection or complement are only substituted in simple cases.
If a group can't be expanded at all places, its definition is left unchanged.

Changes are done in place, no backup files are created. But only
changed files are touched.

# OPTIONS

**-f**, **--file** file
:   Read GROUP-NAMES from file.

**-q**, **--quiet**
:   Don't print status messages.

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

A call to

`expand-group netspoc/ group:g1 group:g2`

would change this Netspoc configuration:

    ## START
    group:g1 = host:a;
    group:g2 = group:g1, host:b;
    group:g3 = group:g2, host:c;
    ## END

like this:

    ## START
    group:g3 =
    host:a,
    host:b,
    host:c,
    ;
    ## END

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
with this program; if !, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

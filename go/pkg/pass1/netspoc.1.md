# netspoc 1 "" Netspoc "User Manual"

# NAME

Netspoc - A Network Security Policy Compiler

# SYNOPSIS

netspoc [options] IN-DIR|IN-FILE [CODE-DIR]

# DESCRIPTION

Compile all files from IN-DIR or from a single IN-FILE.
Output is generated in CODE-DIR.
If no CODE-DIR is given, no output is generated; only errors are checked.

# OPTIONS

**--auto_default_route**[=false]
: Generate default routes to minimize number of routing entries.

**--check_duplicate_rules** 0|1|warn
: Check for duplicate rules.

**--check_empty_files** 0|1|warn
: Check for files without content.

**--check_identical_services** 0|1|warn
: Check for services that have identical rule definitions and should be merged
  into one single service.

**--check_policy_distribution_point** 0|1|warn
: Check that attribute `policy_distribution_point` can be derived
  for all managed devices.

**--check_redundant_rules** 0|1|warn
: Check for redundant rules.

**--check_fully_redundant_rules** 0|1|warn
: Check for fully redundant rules.
  This warning can't be disabled by attribute `overlaps`.

**--check_service_empty_user** 0|1|warn
: Check for services with empty user.

**--check_service_multi_owner** 0|1|warn
: Check for services where multiple owners have been derived.

**--check_service_unknown_owner** 0|1|warn
: Check for services where owner can't be derived.

**--check_service_useless_attribute** 0|1|warn
: Check for useless attributes
  `has_unenforceable | identical_body | multi_owner | overlaps | unknown_owner`
  in services.

**--check_subnets** 0|1|warn
: Check for subnets which aren't declared with attribute `subnet_of`.

**--check_supernet_rules** 0|1|warn
: Check for missing supernet rules.

**--check_transient_supernet_rules** 0|1|warn
: Check for transient supernet rules.

**--check_unenforceable** 0|1|warn
: Check for unenforceable rules, i.e. no managed device between src and dst.

**--check_unused_groups** 0|1|warn
: Check for unused groups and protocolgroups.

**--check_unused_protocols** 0|1|warn
: Check for unused potocol definitions.

**--max_errors** INT
: Abort after this many errors.

**--concurrency_pass1** INT
: Use concurrency in pass1 of Netspoc if value is > 1.

**--concurrency_pass2** INT
: Use concurrency when generating code files for devices,
  using at most the given number of threads.

**--debug_pass2** NAME
: Argument is filename of device, e.g. NAME or ipv6/NAME.
  If given, code is generated only for this single file.

**-q**, **--quiet**
: Don't print progress messages.

**--time_stamps**[=false]
: Print progress messages with time stamps.

**-h**, **--help**
: Print a brief help message and exit.

# COPYRIGHT AND DISCLAIMER

(C) 2025 by Heinz Knutzen, heinz.knutzen@googlemail.com

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

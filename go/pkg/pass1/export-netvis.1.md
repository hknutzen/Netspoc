# export-netvis 1 "" Netspoc "User Manual"

# NAME

export-netvis - Export network topology to JSON format for visualization

# SYNOPSIS

export-netvis [options] FILE|DIR

# DESCRIPTION

This program reads a Netspoc configuration and exports the network topology
as JSON data to **standard output (STDOUT)**. The output includes information 
about networks, routers, and their interconnections, which can be used for 
visualization purposes.

The JSON output contains:

- **Networks**: IP addresses, areas, connected routers, and hosts
- **Routers**: Type (managed/routing_only), connected networks, and tunnel information
- **Relationships**: Neighbor connections between networks and routers

This data can be used by visualization tools to create graphical representations
of the network topology.

# OPTIONS

**-q**, **--quiet**
:   Don't print progress messages.

**-h**, **--help**
:   Print a brief help message and exit.

# OUTPUT FORMAT

The output is a JSON object with two main sections:

- `network`: A map of network objects with their properties and neighbors
- `router`: A map of router objects with their properties and connected networks

Each network object includes:
- `id`: Network name
- `type`: Object type (network)
- `address`: IP address/prefix
- `in_area`: Area name (if applicable)
- `neighbors`: List of connected routers
- `hosts`: List of hosts in the network

Each router object includes:
- `id`: Router name
- `type`: Router type (managed model or routing_only)
- `neighbors`: List of connected networks
- `is_tunnel`: Indicates if connection is a tunnel

# EXAMPLES

Export topology from Netspoc configuration in directory `netspoc/`:

`export-netvis netspoc/`

Export topology quietly without progress messages:

`export-netvis -q netspoc/`

# COPYRIGHT AND DISCLAIMER

(c) 2025 by Dominik Kunkel, netspoc@drachionix.eu

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
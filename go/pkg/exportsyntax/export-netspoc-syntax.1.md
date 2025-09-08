# export-netspoc-syntax 1 "" Netspoc "User Manual"

# NAME

export-netspoc-syntax - Write Netspoc configuration as JSON to STDOUT

# SYNOPSIS

export-netspoc-syntax [options] netspoc-data [TYPE:NAME|TYPE: ...]

# DESCRIPTION

export-netspoc-syntax writes selected toplevel definitions as JSON to Stdout.

If a typed name is given, this object is written.
If a type with empty name is given, all objects of this type are written.
If no argument is given, all toplevel definitions are written.

Each definition is written as JSON object with key value pairs.
Definitions are grouped by TYPE, even if only a single object is exported.

# OPTIONS

**-q**, **--quiet**
:   Flag is ignored

**-h**, **--help**
:   Print a brief help message and exit.

# EXAMPLES

With this Netspoc configuration

    #START
    network:n1 = {
     ip = 10.1.1.0/24;
     host:h1 = { ip = 10.1.1.11; owner = o1; }
     host:h2 = { range = 10.1.1.12-10.1.1.23; }
    }
    router:r1 = {
     managed;
     model = ASA;
     interface:n1 = {ip = 10.1.1.1; virtual = {ip = 10.1.1.9;} hardware = n1;}
    }
    #END

`export-netspoc-syntax netspoc/`

would generate this output:

    {"network":[
     {"name":"network:n1",
      "ip": [ "10.1.1.0/24" ],
      "hosts": {
       "host:h1": {
        "ip": [ "10.1.1.11" ],
        "owner": [ "o1" ]
       },
       "host:h2": {
        "range": [ "10.1.1.12 - 10.1.1.23" ]
       }
      }
     }],
     "router":[
     {"name":"router:r1",
      "managed": null,
      "model":["ASA"],
      "interfaces":{
       "interface:n1":{
        "ip": [ "10.1.1.1" ],
        "hardware": [ "n1" ],
        "virtual": { "ip": [ "10.1.1.9" ] }
       }
      }
     }]
    }

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

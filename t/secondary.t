#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Secondary optimization to largest safe network';
############################################################

$in = <<'END';
network:all_10 = { ip = 10.0.0.0/8; has_subnets; }
network:super = { ip = 10.1.0.0/16; has_subnets; }
any:10_1_0-1 = { ip = 10.1.0.0/17; link = network:super; }

router:u = {
 interface:all_10;
 interface:super;
 interface:sub = { ip = 10.1.2.1; }
}

network:sub = { ip = 10.1.2.0/24; subnet_of = network:super; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:sub = { ip = 10.1.2.241; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}

network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed = secondary;
 model = IOS, FW;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
 interface:loop = { ip = 10.0.0.1; hardware = Loopback1; loopback; }
}

network:dst = { 
 ip = 10.9.9.0/24; 
 host:server = { ip = 10.9.9.9; }
}

service:test = {
 user = network:sub;
 permit src = user;
        dst = host:server, interface:r2.loop;
        prt = tcp 80;
}
END

$out = <<'END';
--r2
ip access-list extended Ethernet5_in
 permit ip 10.1.0.0 0.0.255.255 host 10.0.0.1
 deny ip any host 10.9.9.1
 permit ip 10.1.0.0 0.0.255.255 10.9.9.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No optimization if sub-net of sub-net is outside of zone';
############################################################

$in = <<'END';
network:src = { ip = 10.1.1.0/24; }

# src must not be allowed to access subsub.
router:r1 = {
 managed = secondary;
 model = IOS, FW;
 interface:src = { ip = 10.1.1.1; hardware = Ethernet1; }
 interface:subsub = { ip = 10.9.9.49; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}

network:subsub = { ip = 10.9.9.48/29; subnet_of = network:sub; }
network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
}

network:dst = { 
 ip = 10.9.9.0/24; 
 host:server = { ip = 10.9.9.9; }
}

router:u = {
 interface:dst;
 interface:sub = { ip = 10.9.9.33; }
}

network:sub = { ip = 10.9.9.32/27;  subnet_of = network:dst; }

service:test = {
 user = network:src;
 permit src = user;
        dst = host:server;
        prt = tcp 80;
}
END

$out = <<'END';
--r1
ip access-list extended Ethernet1_in
 permit ip 10.1.1.0 0.0.0.255 host 10.9.9.9
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Don't optimize rule if any rule starts behind secondary router";
############################################################

$in = <<'END';
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; }}

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.2.2.1; hardware = vlan2; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.2.2.2; hardware = vlan1; }
 interface:n3 = { ip = 10.2.3.2; hardware = vlan2; }
}

network:n3 = { ip = 10.2.3.0/27; host:h3 = { ip = 10.2.3.4; }}

service:n1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 22;
}
END

$out = <<'END';
--r1
! [ ACL ]
access-list vlan1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list vlan1_in extended deny ip any any
access-group vlan1_in in interface vlan1
END
#--r2
#! [ ACL ]
#access-list vlan1_in extended permit tcp any 10.2.3.0 255.255.255.224 eq 22
#access-list vlan1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.#255.255.224 eq 80
#access-list vlan1_in extended deny ip any any
#access-group vlan1_in in interface vlan1
#END


Test::More->builder->
    todo_start("Check aggregate rules during secondary optimization");
test_run($title, $in, $out);
Test::More->builder->todo_end;

############################################################
done_testing;

#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($topo, $title, $in, $out);

############################################################
$title = 'Auto interface of network';
############################################################

$topo = <<'END';
network:a = { ip = 10.0.0.0/24; }
router:r1 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.1; hardware = e1; }
 interface:b1 = { ip = 10.1.1.1; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.2; hardware = f1; }
 interface:b2 = { ip = 10.1.2.1; hardware = f0; }
}
network:b1 = { ip = 10.1.1.0/24; }
network:b2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:b1 = { ip = 10.1.1.2; }
 interface:b2 = { ip = 10.1.2.2; }
 interface:b3 = { ip = 10.1.3.1; }
}
network:b3 = { ip = 10.1.3.0/24; }
any:b = { link = network:b1; }
END

$in = $topo . <<'END';
service:test1 = {
 user = interface:[network:b1].[auto],
        interface:[managed & network:b2].[auto],
        interface:[network:b3].[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}

service:test2 = {
 user = interface:[network:b3].[auto];
 permit src = user; dst = interface:[network:a].[auto]; prt = tcp 23;
}
END

$out = <<'END';
--r1
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp host 10.1.3.1 host 10.0.0.1 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.3.1 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.1 eq 22
 deny ip any any
--
ip access-list extended e0_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp host 10.1.3.1 host 10.0.0.1 eq 23
 permit tcp host 10.1.3.1 host 10.0.0.2 eq 23
 deny ip any any
--r2
ip access-list extended f1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.1 eq 22
 permit tcp host 10.1.3.1 host 10.0.0.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--
ip access-list extended f0_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.1 eq 22
 permit tcp host 10.1.3.1 host 10.0.0.2 eq 23
 permit tcp host 10.1.3.1 host 10.0.0.1 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface of router';
############################################################

$in = $topo . <<'END';
service:test2 = {
 user = interface:u.[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.2 eq 23
 deny ip any any
--r2
! [ ACL ]
ip access-list extended f1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.2 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'All interfaces of aggregate';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[any:b].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.1 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'All interfaces of implicit aggregate';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[any:[network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Managed interfaces of implicit aggregate';
############################################################
# Border interfaces of zone are managed by definition.

$in = $topo . <<'END';
service:s = {
 user = interface:[managed & any:[network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Interfaces of matching implicit aggregate';
############################################################

$in = $topo . <<END;
service:s = {
 user = interface:[any:[ip = 10.1.0.0/16 & network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
Error: Must not use interface:[..].[all]
 with any:[ip=10.1.0.0/16 & network:b1] having ip/mask
 in user of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'Auto interfaces of aggregate';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[any:b].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
Error: Must not use interface:[any:..].[auto] in user of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'All interfaces of network';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Managed interfaces of network';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[managed & network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore short interface of network';
############################################################

($in = $topo) =~ s/\Qinterface:b1 = { ip = 10.1.1.2; }\E/interface:b1;/;
$in .= <<'END';
service:s = {
 user = interface:[network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<'END';
Warning: Ignoring short interface:u.b1 in dst of rule in service:s
--r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 23
 deny ip any any
END

test_warn($title, $in, $out);

############################################################
$title = 'All interfaces from auto interface of network';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[interface:[network:b1].[auto]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<"END";
Error: Can\'t use interface:[network:b1].[auto] inside interface:[..].[all] of user of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'All interfaces from auto interface of router';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[interface:u.[auto]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<"END";
-- r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.3.1 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface from auto interface of router';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[interface:u.[auto]].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<"END";
-- r1
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.2 eq 23
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface from auto interface';
############################################################

$in = $topo . <<'END';
service:s = {
 user = interface:[interface:[network:b1].[auto]].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out = <<"END";
Error: Can\'t use interface:[network:b1].[auto] inside interface:[..].[auto] of user of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'Auto interfaces in nested loop';
############################################################

$in = <<'END';
network:Serv = {ip = 10.10.0.0/20;}

router:ZT45 = {
 interface:Serv = {ip = 10.10.0.3; virtual = {ip = 10.10.1.2;}}
 interface:ZT45 = {ip = 10.21.7.14;}
}
network:ZT45 = {ip = 10.21.7.12/30;}

router:LV41 = {
 interface:Serv = {ip = 10.10.0.2; virtual = {ip = 10.10.1.2;}}
 interface:LV41 = {ip = 10.22.8.1;}
}
network:LV41 = {ip = 10.22.8.0/30;}

network:Trns = {ip = 10.24.1.20/30;}
network:Crss = {ip = 10.24.2.20/30;}

router:LV96 = {
 interface:Trns = {ip = 10.24.1.22;}
 interface:Crss = {ip = 10.24.2.22;}
 interface:LV96 = {ip = 10.22.8.22;}
}

router:ZT21 = {
 interface:Trns = {ip = 10.24.1.21;}
 interface:Crss = {ip = 10.24.2.21;}
 interface:ZT21 = {ip = 10.21.7.21;}
}
network:LV96 = {ip = 10.22.8.20/30;}
network:ZT21 = {ip = 10.21.7.20/30;}

router:Plus = {
 interface:LV41 = {ip = 10.22.8.2;}
 interface:LV96 = {ip = 10.22.8.21;}
 interface:Plus = {ip = 10.23.8.6;}
}
router:Base = {
 interface:ZT45	= {ip = 10.21.7.13;}
 interface:ZT21 = {ip = 10.21.7.22;}
 interface:Base = {ip = 10.23.7.6;}
}
network:Plus = {ip = 10.23.8.4/30;}
network:Base = {ip = 10.23.7.4/30;}
router:R5 = {
 interface:Plus = {ip = 10.23.8.5;}
 interface:Base = {ip = 10.23.7.5;}
 interface:G112 = {ip = 10.23.6.5;}
}

network:G112 = {ip = 10.23.6.4/30;}
router:FW = {
 managed;
 model = ASA;
 interface:G112 = {ip = 10.23.6.6; hardware = outside; }
 interface:Mgmt = {ip = 10.11.11.13; hardware = inside;}
}
network:Mgmt = {ip = 10.11.11.0/24;}

service:IPSEC = {
 user = interface:R5.[auto],
        interface:Base.[auto],
        interface:Plus.[auto],
        interface:ZT21.[auto],
        interface:LV96.[auto],
        interface:ZT45.[auto],
        interface:LV41.[auto],
        ;
 permit	src = network:Mgmt;
	dst = user;
	prt = tcp 22;
}
END

# Expect
# only interface:G112 of router:R5
# and all interfaces of other routers.

$out = <<'END';
--FW
object-group network g0
 network-object 10.10.0.2 255.255.255.254
 network-object host 10.21.7.13
 network-object host 10.21.7.14
 network-object host 10.21.7.21
 network-object host 10.21.7.22
 network-object host 10.22.8.1
 network-object host 10.22.8.2
 network-object host 10.22.8.21
 network-object host 10.22.8.22
 network-object host 10.23.6.5
 network-object host 10.23.7.6
 network-object host 10.23.8.6
 network-object host 10.24.1.21
 network-object host 10.24.1.22
 network-object host 10.24.2.21
 network-object host 10.24.2.22
access-list inside_in extended permit tcp 10.11.11.0 255.255.255.0 object-group g0 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'Different paths to auto interface with same result';
############################################################

$in = <<'END';
network:n1 = {ip = 10.1.1.0/24;}

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = {ip = 10.1.1.1;hardware = n1;}
 interface:n2 = {ip = 10.1.2.1;hardware = n2;}
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:h2 = { ip = 10.1.2.10;}
}

router:r2 = {
 model = Linux;
 managed;
 interface:n2 = {ip = 10.1.2.2; hardware = n2;}
}

service:s1 = {
 user = host:h2, network:n1;
 permit src = user;
	dst = interface:r2.[auto];
	prt = udp 161;
}
END

$out = <<'END';
--r2
# [ ACL ]
:c1 -
-A c1 -j ACCEPT -s 10.1.2.10
-A c1 -j ACCEPT -s 10.1.1.0/24
--
:n2_self -
-A n2_self -g c1 -s 10.1.0.0/22 -d 10.1.2.2 -p udp --dport 161
-A INPUT -j n2_self -i n2
END

test_run($title, $in, $out);

############################################################
$title = 'Different paths to auto interface with different result';
############################################################

$in = <<'END';
network:n1 = {ip = 10.1.1.0/24;}

router:r1 = {
 model = Linux;
 managed;
 interface:n1 = {ip = 10.1.1.1;hardware = n1;}
 interface:n2 = {ip = 10.1.2.1;hardware = n2;}
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:h2 = { ip = 10.1.2.10;}
}

service:s1 = {
 user = host:h2, network:n1;
 permit src = user;
	dst = interface:r1.[auto];
	prt = udp 161;
}
END

$out = <<'END';
--r1
# [ ACL ]
:n1_self -
-A n1_self -j ACCEPT -s 10.1.1.0/24 -d 10.1.1.1 -p udp --dport 161
-A INPUT -j n1_self -i n1
--
:n2_self -
-A n2_self -j ACCEPT -s 10.1.2.10 -d 10.1.2.1 -p udp --dport 161
-A INPUT -j n2_self -i n2
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface with pathrestriction';
############################################################
# Would not find result if search starts at router.

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = Vlan20; }
 interface:n2 = { ip = 10.1.2.1; hardware = G0/1;
 }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = Vlan20; }
 interface:n2 = { ip = 10.1.2.2; hardware = G0/1;  }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.70; hardware = E0; }
 interface:n3 = { ip = 10.1.3.1; hardware = E1; }
}
network:n3 = { ip = 10.1.3.0/24; }

pathrestriction:restrict1 =
 interface:r1.n1,
 interface:r3.n2,
;
pathrestriction:restrict2 =
 interface:r2.n1,
 interface:r3.n2,
;

service:test = {
 user = network:n1;
 permit src = user; dst = interface:r3.[auto]; prt = tcp 80;
}
END

$out = <<'END';
--r1
! Vlan20_in
access-list Vlan20_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.1.2.70 eq 80
access-list Vlan20_in extended deny ip any4 any4
access-group Vlan20_in in interface Vlan20
--r2
! [ ACL ]
ip access-list extended Vlan20_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.70 eq 80
 deny ip any any
--r3
! [ ACL ]
ip access-list extended E0_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.70 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore interface with pathrestriction at border of loop (1)';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
}

network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }

router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2 ;}
}

network:n2 = { ip = 10.1.2.0/24; }

pathrestriction:p =
 interface:r1.n1,
 interface:r1.t2,
;
service:test = {
 user = interface:r1.[auto];
 permit src = network:n2; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r2
! n2_in
object-group network g0
 network-object host 10.9.1.2
 network-object host 10.9.2.2
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 object-group g0 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore interface with pathrestriction at border of loop (2)';
############################################################

$in = <<'END';

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3  = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

pathrestriction:p1 = interface:r1.n2, interface:r2.n2;

service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Find auto interface with pathrestriction in loop';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3;}
}

network:n3 = { ip = 10.1.3.0/24; }

pathrestriction:p =
 interface:r1.n2,
 interface:r2.n2,
;

service:s = {
 user = interface:r1.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r2
! n3_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.2.1
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 object-group g0 eq 22
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_run($title, $in, $out);

############################################################
$title = 'Find auto interface with pathrestriction at border of loop at zone';
############################################################

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2;  }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }

pathrestriction:restrict1 =
 interface:r2.n1,
 interface:r3.n2,
;
service:s1 = {
 user = interface:r3.[auto];
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<'END';
--r2
ip access-list extended n2_in
 deny ip any host 10.1.1.2
 permit tcp host 10.1.2.3 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple auto interfaces in src and dst';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = user;
        dst = interface:r3.[auto], interface:r4.[auto];
        prt = tcp 22;
}
END

$out = <<'END';
--r1
! n1_in
object-group network g0
 network-object host 10.1.1.2
 network-object host 10.1.2.1
object-group network g1
 network-object host 10.1.2.2
 network-object host 10.1.3.1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n1_in extended permit tcp object-group g0 object-group g1 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- r2
! n1_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.4.2
object-group network g1
 network-object host 10.1.2.2
 network-object host 10.1.3.1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n1_in extended permit tcp object-group g0 object-group g1 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r3
! n2_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.1.2
 network-object host 10.1.2.1
 network-object host 10.1.4.2
object-group network g1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n2_in extended permit tcp object-group g0 object-group g1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- r4
ip access-list extended n3_in
 permit tcp host 10.1.1.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.4.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.4.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.2.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.2 eq 22
 deny ip any any
--
ip access-list extended n4_in
 permit tcp host 10.1.1.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.4.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.4.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.2.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.2.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.3.1 eq 22
 permit tcp host 10.1.4.2 host 10.1.2.2 eq 22
 permit tcp host 10.1.4.2 host 10.1.3.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.2.2 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.2.2 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple auto interfaces in src and dst with pathrestriction';
############################################################
# pathrestriction leads to more complicated expansion of auto interfaces,
# because result is different for different destinations.
$in .= <<'END';
pathrestriction:r = interface:r1.n4, interface:r3.n3;
END

$out = <<'END';
--r1
! n1_in
object-group network g0
 network-object host 10.1.1.2
 network-object host 10.1.2.1
object-group network g1
 network-object host 10.1.3.1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n1_in extended permit tcp object-group g0 object-group g1 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n1_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.4.2
object-group network g1
 network-object host 10.1.3.1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n1_in extended permit tcp object-group g0 host 10.1.2.2 eq 22
access-list n1_in extended permit tcp host 10.1.1.1 object-group g1 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r3
! n2_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.1.2
 network-object host 10.1.2.1
object-group network g1
 network-object host 10.1.3.2
 network-object host 10.1.4.1
access-list n2_in extended permit tcp object-group g0 object-group g1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r4
! [ ACL ]
ip access-list extended n3_in
 permit tcp host 10.1.1.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.2.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.4.1 eq 22
 deny ip any any
--
ip access-list extended n4_in
 permit tcp host 10.1.1.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.2 eq 22
 permit tcp host 10.1.2.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.3.2 eq 22
 permit tcp host 10.1.1.1 host 10.1.4.1 eq 22
 permit tcp host 10.1.4.2 host 10.1.4.1 eq 22
 permit tcp host 10.1.1.1 host 10.1.3.1 eq 22
 permit tcp host 10.1.4.2 host 10.1.2.2 eq 22
 permit tcp host 10.1.4.2 host 10.1.3.1 eq 22
 permit tcp host 10.1.2.1 host 10.1.3.1 eq 22
 permit tcp host 10.1.1.2 host 10.1.3.1 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface of internally split router with pathrestriction (1)';
############################################################

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

# r1 is split internally into two parts
# r1 with n1,n2
# r1' with n3
# both connected by unnumbered network.
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

pathrestriction:r =
 interface:r1.n3,
 interface:r2.n3,
;

service:s = {
 user = network:n4;

 # Find split interface r1.n3 from original router:r1
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;

 # Find original router:r1 from split interface:r1.n3
 permit src = user; dst = interface:[interface:r1.n3].[auto]; prt = tcp 23;

 # Check that all interfaces are found.
 permit src = user; dst = interface:r1.[all]; prt = tcp 24;
 permit src = user; dst = interface:[interface:r1.n3].[all]; prt = tcp 25;
}
END

$out = <<'END';
--r2
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n4_in
object-group network g0
 network-object host 10.1.1.1
 network-object host 10.1.3.1
access-list n4_in extended permit tcp 10.1.4.0 255.255.255.0 object-group g0 range 22 25
access-list n4_in extended permit tcp 10.1.4.0 255.255.255.0 host 10.1.2.1 range 24 25
access-list n4_in extended deny ip any4 any4
access-group n4_in in interface n4
--
! n3_in
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface of internally split router with pathrestriction (2)';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n4 = { ip = 10.1.4.2; loopback; }
 interface:n3 = { ip = 10.1.3.2; }
}

network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.9; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}

network:n5 = { ip = 10.1.5.0/24; }

pathrestriction:r =
 interface:r1.n2,
 interface:r2.n3,
;

service:s = {
 user = interface:r2.[auto];
 permit src = network:n5; dst = user; prt = tcp 22;
}
END

# Don't accidently assume, that interface:r2.n3 is located in zone of
# original unmanaged router:r2.
# In this case we would get a path to interface:r2.n3 through router:r1.
$out = <<'END';
--r1
! n2_in
access-list n2_in extended permit tcp 10.1.5.0 255.255.255.0 host 10.1.1.2 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface of internally split router with pathrestriction (3)';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n4 = { ip = 10.1.4.0/24; }

router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n4 = { ip = 10.1.4.2; }
 interface:n3 = { ip = 10.1.3.2; }
}

network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r3 = {
 interface:n2;
 interface:n3;
 interface:n5;
}

network:n5 = { ip = 10.1.5.0/24; }

router:r4 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
}

network:n6 = { ip = 10.1.6.0/24; }

pathrestriction:r =
 interface:r1.n2,
 interface:r2.n3,
;

service:s = {
 user = interface:r2.[auto];
 permit src = network:n6; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r4
object-group network g0
 network-object host 10.1.1.2
 network-object host 10.1.3.2
access-list n6_in extended permit tcp 10.1.6.0 255.255.255.0 object-group g0 eq 22
access-list n6_in extended deny ip any4 any4
access-group n6_in in interface n6
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple interfaces talk to policy_distribution_point (1)';
############################################################

$in = <<'END';
network:a = { ip = 10.0.0.0/24; host:netspoc = { ip = 10.0.0.10; } }
router:r1 =  {
 managed;
 model = IOS,FW;
 policy_distribution_point = host:netspoc;
 routing = manual;
 interface:a = { ip = 10.0.0.1; hardware = e1; }
 interface:b1 = { ip = 10.1.1.1; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.2; hardware = e1; }
 interface:b1 = { ip = 10.1.1.2; hardware = e0; }
}
network:b1 = { ip = 10.1.1.0/24; }

service:test = {
 user = interface:r1.[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r1
! [ IP = 10.0.0.1,10.1.1.1 ]
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple interfaces talk to policy_distribution_point (2)';
############################################################
# Find interfaces in given order n3, n4,
# even if reversed path was already fund previously while
# "Checking and marking rules with hidden or dynamic NAT"

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.111; } }
network:n2 = { ip = 10.1.2.0/30; }
network:n3 = { ip = 10.1.3.0/30; }
network:n4 = { ip = 10.1.4.0/30; }
network:n5 = { ip = 10.1.5.0/27; nat:h = { hidden; } }
network:n6 = { ip = 10.1.6.0/27; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; bind_nat = h; }
}
router:r2 = {
 model = IOS;
 managed;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n3, interface:r2.n4; prt = tcp 22;
 permit src = user; dst = interface:r2.n5;                  prt = tcp 80;
}
END

$out = <<'END';
--r2
! [ IP = 10.1.3.2,10.1.4.1 ]
END

test_run($title, $in, $out);

############################################################
$title = 'Only one interface in loop talks to policy_distribution_point';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; virtual = { ip = 10.1.2.1; } }
}

router:r2 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; virtual = { ip = 10.1.2.1; } }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r3 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.9; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; host:netspoc = { ip = 10.1.3.9; } }

service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r1
! [ IP = 10.1.2.3 ]
--r2
! [ IP = 10.1.2.2 ]
END

test_run($title, $in, $out);

############################################################
# Topology for multiple tests.
############################################################

$topo = <<'END';
network:x = { ip = 10.1.1.0/24; }
router:r = {
 model = IOS, FW;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.1.2.2; hardware = e1; }
}
network:y = { ip = 10.1.2.0/24; }
END

############################################################
$title = 'Interface and auto interface in intersection';
############################################################

$in = $topo . <<'END';
service:test = {
 user = interface:r.[auto] &! interface:r.x;
 permit src = user; dst = network:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless delete of interface:r.x in user of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Interface and auto interface in union';
############################################################

$in = $topo . <<'END';
group:g = interface:r.[auto], interface:r.x, network:y;
service:test = {
 user = group:g &! network:y;
 permit src = user; dst = network:y; prt = tcp 80;
}
END

# Must not trigger error message.
$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Interface and auto network interface';
############################################################

$in = $topo . <<'END';
service:test = {
 user = interface:[network:x].[auto] &! interface:r.x;
 permit src = user; dst = network:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless delete of interface:r.x in user of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Auto interface and auto network interface';
############################################################

$in = $topo . <<'END';
service:test = {
 user = interface:[network:x].[auto] &! interface:r.[auto];
 permit src = user; dst = network:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless delete of interface:r.[auto] in user of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Non conflicting auto network interfaces';
############################################################

$in = $topo . <<'END';
service:test = {
 user = interface:[network:x].[auto] &! interface:[network:y].[auto];
 permit src = user; dst = network:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless delete of interface:[network:y].[auto] in user of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Non conflicting auto network interface with interface';
############################################################

$in = $topo . <<'END';
service:test = {
 user = interface:[network:x].[auto] &! interface:r.y;
 permit src = user; dst = network:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless delete of interface:r.y in user of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Must not use auto interface of host';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test = {
 user = interface:[host:h1].[auto] ;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<"END";
Error: Unexpected type 'Host' in interface:[..] of user of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Unresolvable auto interface and interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test = {
 user = interface:r99.[auto], interface:88.n1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<"END";
Error: Can\'t resolve interface:r99.[auto] in user of service:test
Error: Can\'t resolve interface:88.n1 in user of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Auto interface in wrong context';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}

service:s = {
 user = host:[interface:r1.[auto]],
        network:[interface:r1.[auto]],
        any:[interface:r1.[auto]],
 ;
 permit src = network:n1; dst = user; prt = tcp 22;
}
END

$out = <<"END";
Error: Unexpected type 'Autointerface' in host:[..] of user of service:s
Error: Unexpected type 'Autointerface' in network:[..] of user of service:s
Error: Unexpected type 'Autointerface' in any:[..] of user of service:s
END

test_err($title, $in, $out);

############################################################
done_testing;

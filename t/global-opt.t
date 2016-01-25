#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Find redundant rules';
############################################################

$in = <<'END';
network:n1-sub = { 
 ip = 10.1.1.128/25; 
 subnet_of = network:n1;
 host:h1 = { ip = 10.1.1.130; } 
}

router:u = {
 interface:n1-sub;
 interface:n1;
}

network:n1 = { ip = 10.1.1.0/24; }

any:a1 = { link = network:n1; }

router:filter = {
 managed;
 model = Linux;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:n2 = { ip = 10.2.2.1; hardware = VLAN2; }
 interface:n3 = { ip = 10.3.3.1; hardware = VLAN3; }
}

network:n2 = { 
 ip = 10.2.2.0/24; 
 host:h2 = { ip = 10.2.2.10; }
}

any:a2 = { link = network:n2; }

network:n3 = { 
 ip = 10.3.3.0/24; 
 host:h3 = { ip = 10.3.3.10; }
}

any:a3 = { link = network:n3; }

# h1 < n1-sub < n1 < a1
# h2 < n2 < a2
# h3 < n3 < a3
# tcp 80 < tcp 80-90 < tcp < ip

# rule1 <= rule2 if and only if
# rule1[src] <= rule2[src] &&
# rule1[dst] <= rule2[dst] &&
# rule1[prt] <= rule2[prt] &&

# 1a < 1b
service:1a = {
 user = host:h1;
 permit src = user; 
        dst = network:n2; 
        prt = ip;
}

# non redundant
service:1b = {
 user = any:a1;
 permit src = user; 
        dst = network:n2; 
        prt = ip;
}

# non redundant
service:1c = {
 user = host:h1;
 permit src = user; 
        dst = any:a2; 
        prt = tcp 80;
}

# 1d < 1b
service:1d = {
 user = network:n1;
 permit src = user; 
        dst = host:h2; 
        prt = tcp;
}

# 2a < 2b < 2c
service:2a = {
 user = host:h1;
 permit src = user; 
        dst = host:h3;
        prt = tcp 80;
}

service:2b = {
 user = network:n1-sub;
 permit src = user; 
        dst = network:n3;
        prt = tcp 80-90;
}

# non redundant
service:2c = {
 user = network:n1;
 permit src = user; 
        dst = any:a3;
        prt = tcp;
}
END

$out = <<'END';
Warning: Redundant rules in service:1a compared to service:1b:
  permit src=host:h1; dst=network:n2; prt=ip; of service:1a
< permit src=any:a1; dst=network:n2; prt=ip; of service:1b
Warning: Redundant rules in service:1d compared to service:1b:
  permit src=network:n1; dst=host:h2; prt=tcp; of service:1d
< permit src=any:a1; dst=network:n2; prt=ip; of service:1b
Warning: Redundant rules in service:2a compared to service:2b:
  permit src=host:h1; dst=host:h3; prt=tcp 80; of service:2a
< permit src=network:n1-sub; dst=network:n3; prt=tcp 80-90; of service:2b
Warning: Redundant rules in service:2a compared to service:2c:
  permit src=host:h1; dst=host:h3; prt=tcp 80; of service:2a
< permit src=network:n1; dst=any:a3; prt=tcp; of service:2c
Warning: Redundant rules in service:2b compared to service:2c:
  permit src=network:n1-sub; dst=network:n3; prt=tcp 80-90; of service:2b
< permit src=network:n1; dst=any:a3; prt=tcp; of service:2c
END

test_warn($title, $in, $out);

############################################################
$title = 'Relation between src and dst ranges';
############################################################
# p1 < p2 and p1 < p3

$in = <<'END';
protocol:p1 = udp 123:123;
protocol:p2 = udp 1-65535:123;
protocol:p3 = udp 123:1-65535;
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
  model = IOS, FW;
  managed;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:t1 = {
  user = network:n1;
  permit src = user; dst = network:n2; prt = protocol:p1, protocol:p2, protocol:p3;
}
END

$out = <<'END';
Warning: Redundant rules in service:t1 compared to service:t1:
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p3; of service:t1
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p2; of service:t1
END

test_warn($title, $in, $out);

############################################################
$title = 'Range spans whole network';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24; 
 host:range  = { range = 10.1.1.0 - 10.1.1.255; }
}

router:u = {
 interface:n1;
 interface:t1 = { ip = 10.9.1.1; }
}

network:t1 = { ip = 10.9.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

service:test2 = {
 user = host:range;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
END

$out = <<'END';
Warning: Use network:n1 instead of host:range
 because both have identical address
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test1
< permit src=network:n1; dst=network:n2; prt=tcp 80-90; of service:test2
END

test_warn($title, $in, $out);

############################################################
$title = 'Redundant combined hosts';
############################################################
# Must recognize combined subnet as redundant.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = {ip = 10.1.2.50;}
 host:h2 = {ip = 10.1.2.51;}
}

service:s1 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user; dst = host:h1; prt = tcp 80;
}
service:s2 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! [ ACL ]
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
done_testing;

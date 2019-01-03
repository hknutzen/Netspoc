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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
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
Warning: service:1a is fully redundant
Warning: service:1d is fully redundant
Warning: service:2a is fully redundant
Warning: service:2b is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Redundant rules having protocols with and without modifiers';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

protocol:Ping_Net = icmp 8, src_net, dst_net, overlaps;
protocol:NTP = udp 123;


service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = protocol:NTP;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = udp 123, protocol:Ping_Net;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
Warning: Redundant rules in service:s2 compared to service:s3:
  permit src=network:n1; dst=network:n2; prt=protocol:Ping_Net; of service:s2
< permit src=network:n1; dst=network:n2; prt=ip; of service:s3
  permit src=network:n1; dst=network:n2; prt=udp 123; of service:s2
< permit src=network:n1; dst=network:n2; prt=ip; of service:s3
Warning: service:s2 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Find fully redundant rules even if protocol suppresses warning';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.2; }}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

protocol:Ping_Net = icmp 8, src_net, dst_net, overlaps;

service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocol:Ping_Net;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = protocol:Ping_Net;
}
END

$out = <<'END';
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Show all redundant rules, not only the smallest one';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp;
}
service:s2a = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2b = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:s2a compared to service:s1:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2a
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s2b compared to service:s1:
  permit src=network:n1; dst=host:h2; prt=tcp; of service:s2b
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s3 compared to service:s1:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s3 compared to service:s2a:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2a
Warning: Redundant rules in service:s3 compared to service:s2b:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=host:h2; prt=tcp; of service:s2b
Warning: service:s2a is fully redundant
Warning: service:s2b is fully redundant
Warning: service:s3 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Fully redundant rule: multi redundant and duplicate';
############################################################

$in = <<'END';
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s2, service:s3;
 user = network:n1;
 # duplicate
 permit src = user; dst = network:n2; prt = tcp 80;
 # redundant
 permit src = user; dst = network:n2; prt = tcp 81;
 # redundant with log
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}

service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 90;
}

service:s3 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 81;
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}
END

$out = <<'END';
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Fully redundant rule: mixed redundant and duplicate';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

router:R1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s2;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = icmp 8;
}

service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80, icmp 8;
}
END

$out = <<'END';
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Fully redundant rule: simple duplicates';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 # duplicate, but not found first
 permit src = user; dst = network:n2; prt = tcp 80;
}

END

$out = <<'END';
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Fully redundant rule with reversed overlaps';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 # duplicate, but not found first
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 90;
}
END

$out = <<'END';
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Fully redundant rule without overlaps';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

END

$out = <<'END';
Warning: Duplicate rules in service:s2 and service:s1:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2
Warning: service:s1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Don\'t check for duplicate rules';
############################################################

$out = <<'END';
END

test_warn($title, $in, $out, '--check_duplicate_rules=0');

############################################################
$title = 'Fully redundant rule with multiple duplicates';
############################################################
# Must not count duplicate rule multple times at s1,
# otherwise s1 would accidently be marked as redundant.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s2, service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81, icmp 8;
}
service:s2 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 82, icmp 8;
}
service:s3 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83, icmp 8;
}
END

$out = <<'END';
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Empty service is not shown as fully redundant';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
group:g1 = ;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = '';

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Relation between src and dst ranges';
############################################################
# p1 < p2 and p1 < p3

$in = <<'END';
protocol:p1 = udp 123:123;
protocol:p2 = udp 100-65535:123;
protocol:p3 = udp 123:1-1000;
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
service:t2 = {
  user = network:n1;
  permit src = network:n2; dst = user; prt = protocol:p1, udp 123;
}
END

# Adjacent src ranges are not joined currently.
$out = <<'END';
Warning: Redundant rules in service:t1 compared to service:t1:
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p2; of service:t1
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p3; of service:t1
Warning: Redundant rules in service:t2 compared to service:t2:
  permit src=network:n2; dst=network:n1; prt=protocol:p1; of service:t2
< permit src=network:n2; dst=network:n1; prt=udp 123; of service:t2
-- r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp 10.1.1.0 0.0.0.255 range 100 1000 10.1.2.0 0.0.0.255 eq 123
 permit udp 10.1.1.0 0.0.0.255 gt 1000 10.1.2.0 0.0.0.255 eq 123
 permit udp 10.1.1.0 0.0.0.255 eq 123 10.1.2.0 0.0.0.255 lt 1001
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit udp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 123
 deny ip any any
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
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
Warning: service:test1 is fully redundant
END

test_warn($title, $in, $out, '--check_fully_redundant_rules=warn');

############################################################
$title = 'Redundancy in enclosed port range';
############################################################
# Redundance should be recognized, even if service:s3 isn not defined.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80 - 81;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
#service:s3 = {
# user = network:n2;
# permit src = user; dst = network:n3; prt = tcp 10 - 80;
#}
END

$out = <<'END';
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=host:h1; dst=network:n3; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s2
END

Test::More->builder->
    todo_start("Split port ranges before compare");
test_warn($title, $in, $out);
Test::More->builder->todo_end;

############################################################
done_testing;

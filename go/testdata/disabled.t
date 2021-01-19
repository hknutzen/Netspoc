
############################################################
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; disabled; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Ignore disabled host, network, interface in rule
=INPUT=
${topo}
service:test = {
    user = host:h1, network:n2, interface:r1.n1, interface:r1.[auto];
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Ignore disabled aggregate in rule
=INPUT=
${topo}
any:n1 = { link = network:n1; }
service:test = {
 user = any:n1;
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Ignore disabled area in rule
=INPUT=
${topo}
area:a2 = { border = interface:r1.n2, interface:r2.n2;  }
service:test = {
 user = network:[area:a2];
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Must not disable single interface inside loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
=END=
=ERROR=
Error: interface:r1.n1 must not be disabled,
 since it is part of a loop
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Only warn on unknown network at disabled interface
=INPUT=
#network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=END=
=WARNING=
Warning: Referencing undefined network:n1 from interface:r1.n1
=END=

############################################################
=TITLE=Internally disable hosts of unconnected network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
protocol:Ping_Netz = icmp 8, src_net, dst_net;
service:s = {
 user = network:n1;
 permit src = host:h2; dst = user; prt = protocol:Ping_Netz;
}
=END=
=ERROR=
Error: network:n2 isn't connected to any router
=END=

############################################################
=TITLE=Reached time limit at service
=VAR=input
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
protocol:Ping_Netz = icmp 8, src_net, dst_net;
service:s = {
 disable_at = yyyy-mm-dd;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=INPUT=${input}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=TODO=
sub displace_date {
    my($add_days) = @_;
    my $time = time;
    $time += 60 * 60 * 24 * $add_days;
    my ($sec, $min, $hour, $mday, $mon, $year) = localtime($time);
    $mon += 1;
    $year += 1900;
    my $date = sprintf "%04d-%02d-%02d", $year, $mon, $mday;
    $in =~ s/disable_at =.*/disable_at = $date;/;
}
displace_date(-365);
displace_date(-30);
displace_date(-1);
displace_date(0);
=END=

############################################################
=TITLE=Unreached time limit at service
=INPUT=${input}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=TODO=
displace_date(1);
displace_date(10);
displace_date(1000);
=END

############################################################
=TITLE=Invalid time limit at service
=INPUT=${input}
=SUBST=/yyyy-mm-dd/1-Jan-2020/
=ERROR=
Error: Date expected as yyyy-mm-dd in 'disable_at' of service:s
=END=

############################################################

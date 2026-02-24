############################################################
=TITLE=Self-referencing loop caused by blocked ASA exit
=INPUT=
# Self-referencing loop: two separate loop clusters connected by one router.
# The exit interface of cluster A into cluster B has a pathrestriction.
# clusterNavigation must not enter cluster B when looking for a path
# inside cluster A; it should treat the boundary router as the endpoint.

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
interface:n1;
interface:n2;
interface:n3;
}
router:asa1 = {
managed;
model = ASA;
routing = manual;
interface:n2 = { ip = 10.1.2.1; hardware = n2; }
interface:n3 = { ip = 10.1.3.1; hardware = n3; }
interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
interface:n4;
interface:n5;
}
router:asa2 = {
managed;
model = ASA;
routing = manual;
interface:n4 = { ip = 10.1.4.2; hardware = n4; }
interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
pathrestriction:pr1 = interface:asa1.n4, interface:r1.n3;
service:test = {
user = network:n1;
permit src = user; dst = network:n4; prt = ip;
}

=PARAMS=network:n1 network:n4
=OUTPUT=
["network:n1","network:n2","network:n3","network:n4","router:asa1","router:r1"]
=END=

############################################################
=TITLE=Cross-cluster pathrestriction with all-managed routers
=INPUT=
# Two loop clusters connected via network:n2.
# Loop A: n1-r1-n2-r2-n1. Loop B: n2-r3-n3-r4-n4-r3-n2.
# Pathrestriction pr1 on r3.n2 and r4.n4 blocks one side of loop B.
# A valid path still exists via the free side of loop B: n3.

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.4; hardware = n3; }
 interface:n4 = { ip = 10.1.4.4; hardware = n4; }
}
pathrestriction:pr1 = interface:r3.n2, interface:r4.n4;
service:test = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = ip;
}

=PARAMS=network:n1 network:n4
=OUTPUT=
["network:n1","network:n2","network:n3","network:n4","router:r1","router:r2","router:r3","router:r4"]
=END=
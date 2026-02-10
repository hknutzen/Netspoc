############################################################
=TITLE=Self-referencing loop caused by blocked ASA exit
=INPUT=
# Self-referencing loop warning reproducer.
# Two routers share the same two transit networks.
# The only viable exit from the loop is blocked by pathrestrictions,
# so clusterNavigation sees the loop exit pointing back to itself.

network:FW-INFRA_NI_SERVER-10_65_119_0-27 = { ip = 10.65.119.0/27; }
network:FW-INFRA_INSIDE_TRANSPORT_NI_ASA = { ip = 10.65.105.72/29; }
network:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA = { ip = 10.65.105.80/29; }
network:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_SHARED_ASA = { ip = 10.65.105.112/29; }
network:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA = { ip = 10.65.105.88/29; }
network:FW-INFRA_SHARED_SERVER-10_65_120_64-28 = { ip = 10.65.120.64/28; }
network:FW-INFRA_MGMT_OOB-10_65_107_160-27 = { ip = 10.65.107.160/27; }

router:d38-FW-INFRA010-1@ni = {
 interface:FW-INFRA_INSIDE_TRANSPORT_NI_ASA = { ip = 10.65.105.73; }
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA = { ip = 10.65.105.81; }
 interface:FW-INFRA_NI_SERVER-10_65_119_0-27;
}

router:d38-asa010-fw-infra-ni-1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:FW-INFRA_MGMT_OOB-10_65_107_160-27 = { ip = 10.65.107.181; hardware = management; }
 interface:FW-INFRA_INSIDE_TRANSPORT_NI_ASA = { ip = 10.65.105.76; hardware = INSIDE_TRANSPORT_NI_ASA; }
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA = { ip = 10.65.105.84; hardware = INSIDE_TRANSPORT_SHARED_Inter_NI_ASA; }
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA = { ip = 10.65.105.90; hardware = INSIDE_TRANSPORT_SHARED_ASA; }
}

router:d38-FW-INFRA010-1@SHARED = {
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA = { ip = 10.65.105.89; }
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_SHARED_ASA = { ip = 10.65.105.113; }
 interface:FW-INFRA_SHARED_SERVER-10_65_120_64-28;
}

router:d38-asa010-fw-infra-shared-1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA = { ip = 10.65.105.92; hardware = INSIDE_TRANSPORT_SHARED_ASA; }
 interface:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_SHARED_ASA = { ip = 10.65.105.116; hardware = INSIDE_TRANSPORT_SHARED_Inter_SHARED_ASA; }
}

# Pathrestrictions: mimic the real minimal case
pathrestriction:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA_ni-1 =
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA,
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_INSIDE_TRANSPORT_NI_ASA,
;

pathrestriction:FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA_ni-2 =
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_INSIDE_TRANSPORT_SHARED_Inter_NI_ASA,
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_MGMT_OOB-10_65_107_160-27,
;

# Critical: block asa_ni exit to SHARED_ASA, forcing self-referencing loop
pathrestriction:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA_block =
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA,
 interface:d38-asa010-fw-infra-ni-1.FW-INFRA_MGMT_OOB-10_65_107_160-27,
;

service:test = {
 user = network:FW-INFRA_NI_SERVER-10_65_119_0-27;
 permit src = user; dst = network:FW-INFRA_SHARED_SERVER-10_65_120_64-28; prt = ip;
}
=PARAMS=network:FW-INFRA_NI_SERVER-10_65_119_0-27 network:FW-INFRA_SHARED_SERVER-10_65_120_64-28
=ERROR=
Error: No valid path
 from any:[network:FW-INFRA_INSIDE_TRANSPORT_NI_ASA]
 to any:[network:FW-INFRA_INSIDE_TRANSPORT_SHARED_ASA]
 for rule permit src=network:FW-INFRA_NI_SERVER-10_65_119_0-27; dst=network:FW-INFRA_SHARED_SERVER-10_65_120_64-28; prt=ip;
 Check path restrictions and crypto interfaces.
=END=

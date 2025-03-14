############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model PAN-OS
=END=

############################################################
=TITLE=Need router with management_instance
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1a; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:103; hardware = n1b; }
}
=ERROR=
Error: Must define unmanaged router:r1
 with attribute 'management_instance'
 for router:r1@vsys2
=END=

############################################################
=TITLE=Missing attribute management_instance
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1a; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:103; hardware = n1b; }
}
=ERROR=
Error: Must add attribute 'management_instance' at router:r1
=END=

############################################################
=TITLE=management_instance without model
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 without model
=END=

############################################################
=TITLE=management_instance at wrong model
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = IOS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 of model IOS
=END=

############################################################
=TITLE=management_instance at managed router
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at managed router:r1
=END=

############################################################
=TITLE=management_instance with VRF
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1@vrf = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
=ERROR=
Error: router:r1@vrf with attribute 'management_instance' must not use VRF
=END=

############################################################
=TITLE=management_instance with interface and no IP address
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1;
}
=ERROR=
Error: router:r1 with attribute 'management_instance' needs interface with IP address
=END=

############################################################
=TITLE=management_instance with more than one interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
 interface:n2;
}
=ERROR=
Error: router:r1 with attribute 'management_instance' needs exactly one interface
=END=

############################################################
=TITLE=backup_of references unknown router
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 backup_of = router:r2;
 interface:n1;
}
=WARNING=
Warning: Ignoring undefined router:r2 in 'backup_of' of router:r1
=END=

############################################################
=TITLE=backup_of references non router
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 backup_of = network:n1;
 interface:n1;
}
=ERROR=
Error: Expected type 'router:' in 'backup_of' of router:r1
=END=

############################################################
=TITLE=backup_of without attribute management_instance
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 backup_of = router:r2;
 interface:n1;
}
router:r2 = {
 interface:n1 = { ip6 = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1 without attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (1)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r2;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 interface:n1 = { ip6 = ::a01:102; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r2 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (2)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r0 = {
 interface:n1 = { ip6 = ::a01:102; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r0;
 interface:n1 = { ip6 = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r0 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=More than one backup_of router
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip6 = ::a01:102; }
}
router:r3 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:103; }
}
router:r4 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip6 = ::a01:104; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r2,
 because router:r1 is already 'backup_of' router:r3
Warning: Ignoring attribute 'backup_of' at router:r4,
 because router:r1 is already 'backup_of' router:r3
=END=

############################################################
=TITLE=management_instance without matching managed router is ok
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=WARNING=NONE

############################################################
=TITLE=Managed devices must not use name of device having attribute backup_of
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip6 = ::a01:102; }
}
router:r2@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:103; hardware = n1; }
}
=ERROR=
Error: Must define unmanaged router:r2
 - with attribute 'management_instance'
 - but without attribute 'backup_of'
 for router:r2@vsys2
=END=

############################################################
=TITLE=IPv4 management_instance
=TODO= No IPv6
=INPUT=
-- ipv6/z_sort_after_ipv6
network:n1 = { ip6 = ::a01:100/120; ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; ip6 = ::a01:102; hardware = IN; }
 interface:n2 = { ip6 = ::a01:201; ip6 = ::a01:201; hardware = OUT; }
}
=OUTPUT=
--ipv6/ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"]}
--ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"]}
=END=

############################################################
=TITLE=IPv6 management_instance
=TODO= No IPv6
=INPUT=
-- ipv6/z_sort_after_ipv6
network:n1 = { ip6 = ::a01:100/120; ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; ip6 = ::a01:200/120; }
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; ip6 = ::a01:102; hardware = IN; }
 interface:n2 = { ip6 = ::a01:201; ip6 = ::a01:201; hardware = OUT; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
=OUTPUT=
--ipv6/ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"]}
--ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"]}
=END=

############################################################
=TITLE=Missing policy_distribution_point at management_instance
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip6 = ::a01:102; }
}
=ERROR=
Error: Missing attribute 'policy_distribution_point' for 2 devices:
 - router:r1
 - router:r2
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Missing rule for policy_distribution_point at management_instance
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip6 = ::a01:102; }
}
=WARNING=
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1
 - router:r2
=END=

############################################################
=TITLE=Inherit policy_distribution_point to management_instance
=INPUT=
area:all = {
 anchor = network:n1;
 router_attributes = {
  policy_distribution_point = host:netspoc;
 }
}
network:n1 = { ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
=END=

############################################################
=TITLE=Ignore policy_distribution_point at managed device
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
}
=WARNING=
Warning: Ignoring attribute 'policy_distribution_point' at router:r1@vsys1
 Add this attribute at 'management_instance' instead
=END=

############################################################
=TITLE=Simple rules, use backup_of
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h10 = { ip6 = ::a01:10a; }
 host:h20 = { ip6 = ::a01:114; }
}
network:n2 = { ip6 = ::a01:200/120;
 host:h30 = { ip6 = ::a01:21e; }
 host:h40 = { ip6 = ::a01:228; }
}
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip6 = ::a01:109; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log_default = start, end;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 log_default = start, setting:Panorama;
 interface:n1 = { ip6 = ::a01:103; hardware = z1; }
 interface:n3 = { ip6 = ::a01:301; hardware = z3; }
}
service:s1 = {
 user = host:h10, host:h20;
 deny src = user; dst = any:[network:n2]; prt = tcp 22;
 permit src = user; dst = host:h30; prt = tcp;
}
protocol:NTP = udp 123:123;
protocol:sPort = udp 123:1-65535;
service:s2 = {
 user = host:h10;
 permit src = user; dst = network:n3; prt = protocol:NTP;
 permit src = user; dst = network:n3; prt = tcp 80, tcp 8080;
}
service:s3 = {
 user = host:h20;
 permit src = user; dst = network:n3; prt = protocol:sPort;
}
service:s4 = {
 user = host:h30, host:h40;
 permit src = user; dst = network:n3; prt = tcp 81;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101","::a01:109"],"name_list":["r1","r2"]}
--ipv6/r1
<?xml version = "1.0" ?>
<config><devices><entry><vsys>
--
<entry name="vsys2">
<rulebase><security><rules>
<entry name="v6r1">
<action>drop</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>v6g0</member></source>
<destination><member>any</member></destination>
<service><member>tcp 22</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>v6g0</member></source>
<destination><member>IP___a01_21e</member></destination>
<service><member>tcp</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<entry name="v6r3">
<action>allow</action>
<from><member>z2</member></from>
<to><member>z1</member></to>
<source>
<member>IP___a01_21e</member>
<member>IP___a01_228</member>
</source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>tcp 81</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="v6g0"><static>
<member>IP___a01_10a</member>
<member>IP___a01_114</member>
</static></entry>
</address-group>
<address>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP___a01_114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP___a01_21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP___a01_228"><ip-netmask>::a01:228/128</ip-netmask></entry>
<entry name="NET___a01_300_120"><ip-netmask>::a01:300/120</ip-netmask></entry>
</address>
<service>
<entry name="tcp"><protocol><tcp><port>1-65535</port></tcp></protocol></entry>
<entry name="tcp 22"><protocol><tcp><port>22</port></tcp></protocol></entry>
<entry name="tcp 81"><protocol><tcp><port>81</port></tcp></protocol></entry>
</service>
</entry>
--
<entry name="vsys3">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP___a01_10a</member></source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>udp 123:123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP___a01_10a</member></source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="v6r3">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP___a01_10a</member></source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>tcp 8080</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="v6r4">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP___a01_114</member></source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>udp 123:1-65535</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="v6r5">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source>
<member>IP___a01_21e</member>
<member>IP___a01_228</member>
</source>
<destination><member>NET___a01_300_120</member></destination>
<service><member>tcp 81</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP___a01_114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP___a01_21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP___a01_228"><ip-netmask>::a01:228/128</ip-netmask></entry>
<entry name="NET___a01_300_120"><ip-netmask>::a01:300/120</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
<entry name="tcp 81"><protocol><tcp><port>81</port></tcp></protocol></entry>
<entry name="tcp 8080"><protocol><tcp><port>8080</port></tcp></protocol></entry>
<entry name="udp 123:1-65535"><protocol><udp><port>1-65535</port><source-port>123</source-port></udp></protocol></entry>
<entry name="udp 123:123"><protocol><udp><port>123</port><source-port>123</source-port></udp></protocol></entry>
</service>
</entry>
--
</vsys></entry></devices></config>
=END=

############################################################
=TITLE=Address group, not shared between different vsys
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h10 = { ip6 = ::a01:10a; }
 host:h20 = { ip6 = ::a01:114; }
}
network:n2 = { ip6 = ::a01:200/120;
 host:h30 = { ip6 = ::a01:21e; }
 host:h40 = { ip6 = ::a01:228; }
}
network:n3 = { ip6 = ::a01:300/120;
 host:h50 = { ip6 = ::a01:332; }
 host:h60 = { ip6 = ::a01:33c; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 log_default = start;
 log:other = end;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log:other = start, end;
 interface:n1 = { ip6 = ::a01:103; hardware = z1; }
 interface:n3 = { ip6 = ::a01:301; hardware = z3; }
}
service:s1 = {
 user = host:h10, host:h20;
 permit src = user; dst = host:h30, host:h40; prt = tcp 80; log = other;
}
service:s2 = {
 user = host:h20, host:h10;
 permit src = user; dst = host:h40, host:h30; prt = udp 123;
}
service:s3 = {
 user = host:h10, host:h20;
 permit src = user; dst = host:h50, host:h60; prt = tcp 80; log = other;
}
service:s4 = {
 user = host:h20, host:h10;
 permit src = user; dst = host:h50, host:h60; prt = ip;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"]}
--ipv6/r1
<?xml version = "1.0" ?>
<config><devices><entry><vsys>
--
<entry name="vsys1">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>v6g0</member></source>
<destination><member>v6g1</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-end>yes</log-end>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>v6g0</member></source>
<destination><member>v6g1</member></destination>
<service><member>udp 123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="v6g0"><static>
<member>IP___a01_10a</member>
<member>IP___a01_114</member>
</static></entry>
<entry name="v6g1"><static>
<member>IP___a01_21e</member>
<member>IP___a01_228</member>
</static></entry>
</address-group>
<address>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP___a01_114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP___a01_21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP___a01_228"><ip-netmask>::a01:228/128</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
<entry name="udp 123"><protocol><udp><port>123</port></udp></protocol></entry>
</service>
</entry>
--
<entry name="vsys2">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>v6g0</member></source>
<destination><member>v6g1</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>v6g0</member></source>
<destination><member>v6g1</member></destination>
<service><member>any</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="v6g0"><static>
<member>IP___a01_10a</member>
<member>IP___a01_114</member>
</static></entry>
<entry name="v6g1"><static>
<member>IP___a01_332</member>
<member>IP___a01_33c</member>
</static></entry>
</address-group>
<address>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP___a01_114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP___a01_332"><ip-netmask>::a01:332/128</ip-netmask></entry>
<entry name="IP___a01_33c"><ip-netmask>::a01:33c/128</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Sort address definitions by IP and mask
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h08 = { ip6 = ::a01:108; }
 host:h09 = { ip6 = ::a01:109; }
 host:h10 = { ip6 = ::a01:10a; }
 host:h11 = { ip6 = ::a01:10b; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
service:s1 = {
 user = host:h08, host:h09, host:h10, host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h08;
 permit src = user; dst = network:n2; prt = tcp 81;
}
service:s3 = {
 user = host:h08, host:h09;
 permit src = user; dst = network:n2; prt = tcp 82;
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET___a01_108_126</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>IP___a01_108</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>tcp 81</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="v6r3">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET___a01_108_127</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>tcp 82</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="IP___a01_108"><ip-netmask>::a01:108/128</ip-netmask></entry>
<entry name="NET___a01_108_127"><ip-netmask>::a01:108/127</ip-netmask></entry>
<entry name="NET___a01_108_126"><ip-netmask>::a01:108/126</ip-netmask></entry>
<entry name="NET___a01_200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
<entry name="tcp 81"><protocol><tcp><port>81</port></tcp></protocol></entry>
<entry name="tcp 82"><protocol><tcp><port>82</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Without rules
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
</address>
<service>
</service>
</entry>
=END=

############################################################
=TITLE=Log deny for PAN-OS
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@v1 = {
 managed;
 model = PAN-OS;
 log_deny = end;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
service:s1 = {
 user = host:h1;
 deny src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
<entry name="v1">
<rulebase><security><rules>
<entry name="v6r1">
<action>drop</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>IP___a01_10a</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-end>yes</log-end>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET___a01_100_120</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET___a01_100_120"><ip-netmask>::a01:100/120</ip-netmask></entry>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="NET___a01_200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Source ports
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h10 = { ip6 = ::a01:10a; }
 host:h20 = { ip6 = ::a01:114; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
protocol:NTP = udp 123:123;
protocol:sPort = udp 1-65535:123;
protocol:highPort = udp 1024-65535:123;
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = protocol:NTP;
 permit src = host:h10; dst = user; prt = protocol:sPort;
 permit src = host:h20; dst = user; prt = protocol:highPort;
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>IP___a01_10a</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>udp 123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>IP___a01_114</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>udp 1024-65535:123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="v6r3">
<action>allow</action>
<from><member>z2</member></from>
<to><member>z1</member></to>
<source><member>NET___a01_200_120</member></source>
<destination><member>NET___a01_100_120</member></destination>
<service><member>udp 123:123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET___a01_100_120"><ip-netmask>::a01:100/120</ip-netmask></entry>
<entry name="IP___a01_10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP___a01_114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="NET___a01_200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
</address>
<service>
<entry name="udp 1024-65535:123"><protocol><udp><port>123</port><source-port>1024-65535</source-port></udp></protocol></entry>
<entry name="udp 123"><protocol><udp><port>123</port></udp></protocol></entry>
<entry name="udp 123:123"><protocol><udp><port>123</port><source-port>123</source-port></udp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=ICMP and numeric protocol
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = icmpv6 8, proto 52;
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET___a01_100_120</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>icmp 8</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="v6r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET___a01_100_120</member></source>
<destination><member>NET___a01_200_120</member></destination>
<service><member>proto 52</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET___a01_100_120"><ip-netmask>::a01:100/120</ip-netmask></entry>
<entry name="NET___a01_200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
</address>
<service>
<entry name="proto 52"><protocol><other>proto 52</other></protocol></entry>
<entry name="icmp 8"><protocol><other>icmp 8</other></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Optimize duplicate IP address
=INPUT=
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a01:101; }
}

network:n1 = { ip6 = ::a01:100/120; }

router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = z1; }
 interface:n2 = { ip6 = ::a01:201; hardware = z2; }
}

network:n2 = { ip6 = ::a01:200/120; }

router:asa = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}

network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }

service:s1 = {
 user = network:n2,
        any:[ip6 = ::a00:0/104 & network:n3],
        any:[ip6 = ::a01:0/112 & network:n4],
        ;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="v6r1">
<action>allow</action>
<from><member>z2</member></from>
<to><member>z1</member></to>
<source><member>NET___a00_0_104</member></source>
<destination><member>NET___a01_100_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET___a00_0_104"><ip-netmask>::a00:0/104</ip-netmask></entry>
<entry name="NET___a01_100_120"><ip-netmask>::a01:100/120</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Add policy distribution point to info file
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120;
 host:netspoc = { ip6 = ::a01:309; }
}
router:r1@vrf = {
 managed;
 model = PAN-OS;
 interface:n1 = { ip6 = ::a01:10b; hardware = IN; }
 interface:n2 = { ip6 = ::a01:201; hardware = OUT; }
}
router:r1 = {
 management_instance;
 policy_distribution_point = host:netspoc;
 model = PAN-OS;
 interface:n1 = { ip6 = ::a01:101; hardware = device; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:admin = {
 user = interface:r1.n1;
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1.info
{"generated_by":"devel","model":"PAN-OS","ip_list":["::a01:101"],"name_list":["r1"],"policy_distribution_point":"::a01:309"}
=END=

############################################################
=TITLE=managed = local not supported
=INPUT=
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip6 = ::a3e:122; }
}

network:n1 = { ip6 = ::a3e:120/123; }
router:r1@vrf = {
 model = PAN-OS;
 managed = local;
 routing = manual;
 filter_only = ::a3e:0/117, ::a3e:f100/120;
 interface:n1 = { ip6 = ::a3e:121; hardware = IN; }
 interface:n2 = { ip6 = ::a3e:f101; hardware = OUT; }
}
network:n2 = { ip6 = ::a3e:f100/125; }
router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip6 = ::a3e:f102; hardware = inside; }
 interface:extern = { ip6 = ::a7d:301; hardware = outside; }
}
network:extern = { ip6 = ::a7d:300/120; }
service:Test = {
 user = network:extern, network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=ERROR=
Error: Must not use 'managed = local' at router:r1@vrf of model PAN-OS
=END=

############################################################
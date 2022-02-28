############################################################
=TITLE=Need VRF
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model PAN-OS
=END=

############################################################
=TITLE=Need management_instance
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = n1a; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:103; hardware = n1b; }
}
=ERROR=
Error: Must define unmanaged router:r1
 with attribute 'management_instance'
 for router:r1@vsys2
=END=

############################################################
=TITLE=management_instance without model
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 without model
=END=

############################################################
=TITLE=management_instance at wrong model
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = IOS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 of model IOS
=END=

############################################################
=TITLE=management_instance at managed router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 management_instance;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at managed router:r1
=END=

############################################################
=TITLE=management_instance with VRF
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1@vrf = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
=ERROR=
Error: router:r1@vrf with attribute 'management_instance' must not use VRF
=END=

############################################################
=TITLE=management_instance with interface and no IP address
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
 interface:n2;
}
=ERROR=
Error: router:r1 with attribute 'management_instance' needs exactly one interface
=END=

############################################################
=TITLE=backup_of references unknown router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 backup_of = router:r2;
 interface:n1;
}
router:r2 = {
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1 without attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (1)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r2;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 interface:n1 = { ip = ::a01:102; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r2 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (2)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r0 = {
 interface:n1 = { ip = ::a01:102; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r0;
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r0 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=More than one backup_of router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = ::a01:102; }
}
router:r3 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:103; }
}
router:r4 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = ::a01:104; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r2,
 because router:r1 is already 'backup_of' router:r3
Warning: Ignoring attribute 'backup_of' at router:r4,
 because router:r1 is already 'backup_of' router:r3
=END=

############################################################
=TITLE=management_instance without matching managed router is ok
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=WARNING=NONE

############################################################
=TITLE=Managed devices must not use name of device having attribute backup_of
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = ::a01:102; }
}
router:r2@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:103; hardware = n1; }
}
=ERROR=
Error: Must define unmanaged router:r2
 - with attribute 'management_instance'
 - but without attribute 'backup_of'
 for router:r2@vsys2
=END=

############################################################
=TITLE=Missing policy_distribution_point at management_instance
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
=ERROR=
Error: Missing attribute 'policy_distribution_point' for 1 devices:
 - router:r1
=END=
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Missing rule for policy_distribution_point at management_instance
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
=END=

############################################################
=TITLE=Inherit policy_distribution_point to management_instance
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n1;
 router_attributes = {
  policy_distribution_point = host:netspoc;
 }
}
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
=END=

############################################################
=TITLE=Ignore policy_distribution_point at managed device
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:10a; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
}
=WARNING=
Warning: Ignoring attribute 'policy_distribution_point' at router:r1@vsys1
 Add this attribute at 'management_instance' instead
=END=

############################################################
=TITLE=Simple rules, use backup_of
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a; }
 host:h20 = { ip = ::a01:114; }
}
network:n2 = { ip = ::a01:200/120;
 host:h30 = { ip = ::a01:21e; }
 host:h40 = { ip = ::a01:228; }
}
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = ::a01:109; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log_default = start, end;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
 interface:n2 = { ip = ::a01:201; hardware = z2; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 log_default = start, setting:Panorama;
 interface:n1 = { ip = ::a01:103; hardware = z1; }
 interface:n3 = { ip = ::a01:301; hardware = z3; }
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
--ipv6/r1
<?xml version = "1.0" ?>
<!--
Generated by Netspoc, version devel
--
[ BEGIN r1, r2 ]
[ Model = PAN-OS ]
[ IP = ::a01:101, ::a01:109 ]
-->
<config><devices><entry><vsys>
--
<entry name="vsys2">
<rulebase><security><rules>
<entry name="r1">
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
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>v6g0</member></source>
<destination><member>IP_::a01:21e</member></destination>
<service><member>tcp</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<entry name="r3">
<action>allow</action>
<from><member>z2</member></from>
<to><member>z1</member></to>
<source>
<member>IP_::a01:21e</member>
<member>IP_::a01:228</member>
</source>
<destination><member>NET_::a01:300_120</member></destination>
<service><member>tcp 81</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="v6g0"><static>
<member>IP_::a01:10a</member>
<member>IP_::a01:114</member>
</static></entry>
</address-group>
<address>
<entry name="IP_::a01:10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP_::a01:114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP_::a01:21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP_::a01:228"><ip-netmask>::a01:228/128</ip-netmask></entry>
<entry name="NET_::a01:300_120"><ip-netmask>::a01:300/120</ip-netmask></entry>
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
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP_::a01:10a</member></source>
<destination><member>NET_::a01:300_120</member></destination>
<service><member>udp 123:123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP_::a01:10a</member></source>
<destination><member>NET_::a01:300_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="r3">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP_::a01:10a</member></source>
<destination><member>NET_::a01:300_120</member></destination>
<service><member>tcp 8080</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="r4">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP_::a01:114</member></source>
<destination><member>NET_::a01:300_120</member></destination>
<service><member>udp 123:1-65535</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
<entry name="r5">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source>
<member>IP_::a01:21e</member>
<member>IP_::a01:228</member>
</source>
<destination><member>NET_::a01:300_120</member></destination>
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
<entry name="IP_::a01:10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP_::a01:114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP_::a01:21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP_::a01:228"><ip-netmask>::a01:228/128</ip-netmask></entry>
<entry name="NET_::a01:300_120"><ip-netmask>::a01:300/120</ip-netmask></entry>
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a; }
 host:h20 = { ip = ::a01:114; }
}
network:n2 = { ip = ::a01:200/120;
 host:h30 = { ip = ::a01:21e; }
 host:h40 = { ip = ::a01:228; }
}
network:n3 = { ip = ::a01:300/120;
 host:h50 = { ip = ::a01:332; }
 host:h60 = { ip = ::a01:33c; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 log_default = start;
 log:other = end;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
 interface:n2 = { ip = ::a01:201; hardware = z2; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log:other = start, end;
 interface:n1 = { ip = ::a01:103; hardware = z1; }
 interface:n3 = { ip = ::a01:301; hardware = z3; }
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
--ipv6/r1
<?xml version = "1.0" ?>
<!--
Generated by Netspoc, version devel
--
[ BEGIN r1 ]
[ Model = PAN-OS ]
[ IP = ::a01:101 ]
-->
<config><devices><entry><vsys>
--
<entry name="vsys1">
<rulebase><security><rules>
<entry name="r1">
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
<entry name="r2">
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
<member>IP_::a01:10a</member>
<member>IP_::a01:114</member>
</static></entry>
<entry name="v6g1"><static>
<member>IP_::a01:21e</member>
<member>IP_::a01:228</member>
</static></entry>
</address-group>
<address>
<entry name="IP_::a01:10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP_::a01:114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP_::a01:21e"><ip-netmask>::a01:21e/128</ip-netmask></entry>
<entry name="IP_::a01:228"><ip-netmask>::a01:228/128</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
<entry name="udp 123"><protocol><udp><port>123</port></udp></protocol></entry>
</service>
</entry>
--
<entry name="vsys2">
<rulebase><security><rules>
<entry name="r1">
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
<entry name="r2">
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
<member>IP_::a01:10a</member>
<member>IP_::a01:114</member>
</static></entry>
<entry name="v6g1"><static>
<member>IP_::a01:332</member>
<member>IP_::a01:33c</member>
</static></entry>
</address-group>
<address>
<entry name="IP_::a01:10a"><ip-netmask>::a01:10a/128</ip-netmask></entry>
<entry name="IP_::a01:114"><ip-netmask>::a01:114/128</ip-netmask></entry>
<entry name="IP_::a01:332"><ip-netmask>::a01:332/128</ip-netmask></entry>
<entry name="IP_::a01:33c"><ip-netmask>::a01:33c/128</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Sort address definitions by IP and mask
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h08 = { ip = ::a01:108; }
 host:h09 = { ip = ::a01:109; }
 host:h10 = { ip = ::a01:10a; }
 host:h11 = { ip = ::a01:10b; }
}
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
 interface:n2 = { ip = ::a01:201; hardware = z2; }
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
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_::a01:108_126</member></source>
<destination><member>NET_::a01:200_120</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>IP_::a01:108</member></source>
<destination><member>NET_::a01:200_120</member></destination>
<service><member>tcp 81</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="r3">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_::a01:108_127</member></source>
<destination><member>NET_::a01:200_120</member></destination>
<service><member>tcp 82</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="IP_::a01:108"><ip-netmask>::a01:108/128</ip-netmask></entry>
<entry name="NET_::a01:108_127"><ip-netmask>::a01:108/127</ip-netmask></entry>
<entry name="NET_::a01:108_126"><ip-netmask>::a01:108/126</ip-netmask></entry>
<entry name="NET_::a01:200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
 interface:n2 = { ip = ::a01:201; hardware = z2; }
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
=TITLE=ICMP and numeric protocol
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = z1; }
 interface:n2 = { ip = ::a01:201; hardware = z2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = icmpv6 8, proto 52;
}
=OUTPUT=
--ipv6/r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_::a01:100_120</member></source>
<destination><member>NET_::a01:200_120</member></destination>
<service><member>icmp 8</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_::a01:100_120</member></source>
<destination><member>NET_::a01:200_120</member></destination>
<service><member>proto 52</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET_::a01:100_120"><ip-netmask>::a01:100/120</ip-netmask></entry>
<entry name="NET_::a01:200_120"><ip-netmask>::a01:200/120</ip-netmask></entry>
</address>
<service>
<entry name="proto 52"><protocol><other>proto 52</other></protocol></entry>
<entry name="icmp 8"><protocol><other>icmp 8</other></protocol></entry>
</service>
</entry>
=END=

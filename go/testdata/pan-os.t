############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model PAN-OS
=END=

############################################################
=TITLE=Need management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1a; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.3; hardware = n1b; }
}
=ERROR=
Error: Must define unmanaged router:r1
 with attribute 'management_instance'
 for router:r1@vsys2
=END=

############################################################
=TITLE=management_instance without model
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 without model
=END=

############################################################
=TITLE=management_instance at wrong model
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = IOS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at router:r1 of model IOS
=END=

############################################################
=TITLE=management_instance at managed router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WARNING=
Warning: Ignoring attribute 'management_instance' at managed router:r1
=END=

############################################################
=TITLE=management_instance with VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1@vrf = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=ERROR=
Error: router:r1@vrf with attribute 'management_instance' must not use VRF
=END=

############################################################
=TITLE=management_instance with interface and no IP address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2;
}
=ERROR=
Error: router:r1 with attribute 'management_instance' needs exactly one interface
=END=

############################################################
=TITLE=backup_of references unknown router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 backup_of = router:r2;
 interface:n1;
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1 without attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (1)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r2;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r2 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=backup_of references router without management_instance (2)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r0 = {
 interface:n1 = { ip = 10.1.1.2; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r0;
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Ignoring attribute 'backup_of' at router:r1,
 because router:r0 hasn't attribute 'management_instance'
=END=

############################################################
=TITLE=More than one backup_of router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = 10.1.1.2; }
}
router:r3 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.3; }
}
router:r4 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r3;
 interface:n1 = { ip = 10.1.1.4; }
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WARNING=NONE

############################################################
=TITLE=Managed devices must not use name of device having attribute backup_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = 10.1.1.2; }
}
router:r2@vsys2 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}
=ERROR=
Error: Must define unmanaged router:r2
 - with attribute 'management_instance'
 - but without attribute 'backup_of'
 for router:r2@vsys2
=END=

############################################################
=TITLE=Missing policy_distribution_point at management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=ERROR=
Error: Missing attribute 'policy_distribution_point' for 1 devices:
 - router:r1
=END=
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Missing rule for policy_distribution_point at management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.10; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
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
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.10; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
=END=

############################################################
=TITLE=Ignore policy_distribution_point at managed device
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.10; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = z1; }
}
=WARNING=
Warning: Ignoring attribute 'policy_distribution_point' at router:r1@vsys1
 Add this attribute at 'management_instance' instead
=END=

############################################################
=TITLE=Simple rules, use backup_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h30 = { ip = 10.1.2.30; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = 10.1.1.9; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log_default = start, end;
 interface:n1 = { ip = 10.1.1.2; hardware = z1; }
 interface:n2 = { ip = 10.1.2.1; hardware = z2; }
}
router:r1@vsys3 = {
 model = PAN-OS;
 managed;
 log_default = start, setting:Panorama;
 interface:n1 = { ip = 10.1.1.3; hardware = z1; }
 interface:n3 = { ip = 10.1.3.1; hardware = z3; }
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
=OUTPUT=
--r1
<?xml version = "1.0" ?>
<!--
Generated by Netspoc, version devel
--
[ BEGIN r1, r2 ]
[ Model = PAN-OS ]
[ IP = 10.1.1.1, 10.1.1.9 ]
-->
<config><devices><entry><vsys>
--
<entry name="vsys2">
<rulebase><security><rules>
<entry name="r1">
<action>drop</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>g0</member></source>
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
<source><member>g0</member></source>
<destination><member>IP_10.1.2.30</member></destination>
<service><member>tcp</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="g0"><static>
<member>IP_10.1.1.10</member>
<member>IP_10.1.1.20</member>
</static></entry>
</address-group>
<address>
<entry name="IP_10.1.1.10"><ip-netmask>10.1.1.10/32</ip-netmask></entry>
<entry name="IP_10.1.1.20"><ip-netmask>10.1.1.20/32</ip-netmask></entry>
<entry name="IP_10.1.2.30"><ip-netmask>10.1.2.30/32</ip-netmask></entry>
</address>
<service>
<entry name="tcp"><protocol><tcp><port>1-65535</port></tcp></protocol></entry>
<entry name="tcp 22"><protocol><tcp><port>22</port></tcp></protocol></entry>
</service>
</entry>
--
<entry name="vsys3">
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z3</member></to>
<source><member>IP_10.1.1.10</member></source>
<destination><member>NET_10.1.3.0_24</member></destination>
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
<source><member>IP_10.1.1.10</member></source>
<destination><member>NET_10.1.3.0_24</member></destination>
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
<source><member>IP_10.1.1.10</member></source>
<destination><member>NET_10.1.3.0_24</member></destination>
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
<source><member>IP_10.1.1.20</member></source>
<destination><member>NET_10.1.3.0_24</member></destination>
<service><member>udp 123:1-65535</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-setting>Panorama</log-setting>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="IP_10.1.1.10"><ip-netmask>10.1.1.10/32</ip-netmask></entry>
<entry name="IP_10.1.1.20"><ip-netmask>10.1.1.20/32</ip-netmask></entry>
<entry name="NET_10.1.3.0_24"><ip-netmask>10.1.3.0/24</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
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
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h30 = { ip = 10.1.2.30; }
 host:h40 = { ip = 10.1.2.40; }
}
network:n3 = { ip = 10.1.3.0/24;
 host:h50 = { ip = 10.1.3.50; }
 host:h60 = { ip = 10.1.3.60; }
}
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 log_default = start;
 log:other = end;
 interface:n1 = { ip = 10.1.1.2; hardware = z1; }
 interface:n2 = { ip = 10.1.2.1; hardware = z2; }
}
router:r1@vsys2 = {
 model = PAN-OS;
 managed;
 log:other = start, end;
 interface:n1 = { ip = 10.1.1.3; hardware = z1; }
 interface:n3 = { ip = 10.1.3.1; hardware = z3; }
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
--r1
<?xml version = "1.0" ?>
<!--
Generated by Netspoc, version devel
--
[ BEGIN r1 ]
[ Model = PAN-OS ]
[ IP = 10.1.1.1 ]
-->
<config><devices><entry><vsys>
--
<entry name="vsys1">
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>g0</member></source>
<destination><member>g1</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-end>yes</log-end>
</entry>
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>g0</member></source>
<destination><member>g1</member></destination>
<service><member>udp 123</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="g0"><static>
<member>IP_10.1.1.10</member>
<member>IP_10.1.1.20</member>
</static></entry>
<entry name="g1"><static>
<member>IP_10.1.2.30</member>
<member>IP_10.1.2.40</member>
</static></entry>
</address-group>
<address>
<entry name="IP_10.1.1.10"><ip-netmask>10.1.1.10/32</ip-netmask></entry>
<entry name="IP_10.1.1.20"><ip-netmask>10.1.1.20/32</ip-netmask></entry>
<entry name="IP_10.1.2.30"><ip-netmask>10.1.2.30/32</ip-netmask></entry>
<entry name="IP_10.1.2.40"><ip-netmask>10.1.2.40/32</ip-netmask></entry>
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
<source><member>g0</member></source>
<destination><member>g1</member></destination>
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
<source><member>g0</member></source>
<destination><member>g1</member></destination>
<service><member>any</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="g0"><static>
<member>IP_10.1.1.10</member>
<member>IP_10.1.1.20</member>
</static></entry>
<entry name="g1"><static>
<member>IP_10.1.3.50</member>
<member>IP_10.1.3.60</member>
</static></entry>
</address-group>
<address>
<entry name="IP_10.1.1.10"><ip-netmask>10.1.1.10/32</ip-netmask></entry>
<entry name="IP_10.1.1.20"><ip-netmask>10.1.1.20/32</ip-netmask></entry>
<entry name="IP_10.1.3.50"><ip-netmask>10.1.3.50/32</ip-netmask></entry>
<entry name="IP_10.1.3.60"><ip-netmask>10.1.3.60/32</ip-netmask></entry>
</address>
<service>
<entry name="tcp 80"><protocol><tcp><port>80</port></tcp></protocol></entry>
</service>
</entry>
=END=

############################################################
=TITLE=Without rules
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = z1; }
 interface:n2 = { ip = 10.1.2.1; hardware = z2; }
}
=OUTPUT=
--r1
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@vsys1 = {
 model = PAN-OS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = z1; }
 interface:n2 = { ip = 10.1.2.1; hardware = z2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = icmp 8, proto 52;
}
=OUTPUT=
--r1
<entry name="vsys1">
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_10.1.1.0_24</member></source>
<destination><member>NET_10.1.2.0_24</member></destination>
<service><member>icmp 8</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
<entry name="r2">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>NET_10.1.1.0_24</member></source>
<destination><member>NET_10.1.2.0_24</member></destination>
<service><member>proto 52</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<address-group>
</address-group>
<address>
<entry name="NET_10.1.1.0_24"><ip-netmask>10.1.1.0/24</ip-netmask></entry>
<entry name="NET_10.1.2.0_24"><ip-netmask>10.1.2.0/24</ip-netmask></entry>
</address>
<service>
<entry name="proto 52"><protocol><other>proto 52</other></protocol></entry>
<entry name="icmp 8"><protocol><other>icmp 8</other></protocol></entry>
</service>
</entry>
=END=

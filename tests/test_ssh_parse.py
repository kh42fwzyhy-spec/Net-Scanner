"""SSH collector parsing, using captured Cisco IOS output (no device needed).

    python -m unittest tests.test_ssh_parse -v
"""

from __future__ import annotations

import unittest

from ntc_templates.parse import parse_output

from switchscan.ssh_collect import COMMANDS, build_device

SAMPLES = {
    "version": """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.9.1r, RELEASE SOFTWARE (P)

access-sw2 uptime is 3 weeks, 2 days, 4 hours, 11 minutes
Uptime for this control processor is 3 weeks, 2 days, 4 hours, 13 minutes
System returned to ROM by Reload Command
System image file is "flash:packages.conf"
Last reload reason: Reload Command

cisco C9200L-48P-4G (ARM64) processor with 1338970K/6147K bytes of memory.
Processor board ID JAE12345678
Base Ethernet MAC Address          : 70:6b:b9:00:00:00
Configuration register is 0x102
""",
    "interfaces": """\

Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1                         notconnect   1            auto   auto 10/100/1000BaseTX
Gi1/0/2                         connected    10         a-full a-1000 10/100/1000BaseTX
Gi1/0/6      phone desk 12      connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/48     uplink to core     connected    trunk        full  1000 1000BaseSX SFP
""",
    "cdp": """\
-------------------------
Device ID: core-sw1.corp.local
Entry address(es):
  IP address: 10.0.99.1
Platform: Arista DCS-7050SX3,  Capabilities: Router Switch
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): Ethernet2
Holdtime : 133 sec

Version :
Arista Networks EOS version 4.31.2F

advertisement version: 2
Management address(es):
  IP address: 10.0.99.1

-------------------------
Device ID: SEP001122334466
Entry address(es):
  IP address: 10.0.20.12
Platform: Cisco IP Phone 8865,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/6,  Port ID (outgoing port): Port 1
Holdtime : 150 sec

Version :
sip8845_65.14-1-1SR1-3

advertisement version: 2

Total cdp entries displayed : 2
""",
    "mac": """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    f875.a420.0001    DYNAMIC     Gi1/0/2
  20    0011.2233.4466    DYNAMIC     Gi1/0/6
  99    001c.7300.0100    DYNAMIC     Gi1/0/48
Total Mac Addresses for this criterion: 4
""",
    "arp": """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.99.1               3   001c.7300.0100  ARPA   Vlan99
Internet  10.0.99.3               -   706b.b900.0000  ARPA   Vlan99
""",
    "vlan": """\

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/1, Gi1/0/3
10   Users                            active    Gi1/0/2, Gi1/0/6
20   Voice                            active
99   Mgmt                             active
1002 fddi-default                     act/unsup
""",
}


def parse_all() -> dict[str, list[dict]]:
    cmds = COMMANDS["cisco_ios"]
    return {k: parse_output(platform="cisco_ios", command=cmds[k], data=v) for k, v in SAMPLES.items()}


class CiscoIosParseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = build_device("10.0.99.3", parse_all())

    def test_identity(self):
        self.assertEqual(self.device.sys_name, "access-sw2")
        self.assertIn("17.9.4a", self.device.sys_descr)

    def test_interfaces(self):
        by_name = {i.name: i for i in self.device.interfaces}
        self.assertEqual(by_name["Gi1/0/2"].oper_status, "up")
        self.assertEqual(by_name["Gi1/0/2"].speed_mbps, 1000)
        self.assertEqual(by_name["Gi1/0/6"].alias, "phone desk 12")
        self.assertEqual(by_name["Gi1/0/1"].oper_status, "down")

    def test_cdp_neighbors(self):
        n = {x.remote_name: x for x in self.device.neighbors}
        core = n["core-sw1.corp.local"]
        self.assertEqual(core.local_port, "GigabitEthernet1/0/48")
        self.assertEqual(core.remote_port, "Ethernet2")
        self.assertEqual(core.remote_mgmt_ip, "10.0.99.1")
        self.assertIn("router", core.capabilities)
        self.assertIn("phone", n["SEP001122334466"].capabilities)

    def test_mac_table_skips_cpu_and_gets_ip_from_arp(self):
        macs = {m.mac: m for m in self.device.mac_table}
        self.assertNotIn("01:00:0c:cc:cc:cc", macs)
        self.assertEqual(macs["f8:75:a4:20:00:01"].vlan, 10)
        self.assertEqual(macs["00:1c:73:00:01:00"].ip, "10.0.99.1")

    def test_vlans_exclude_reserved(self):
        self.assertEqual([v.id for v in self.device.vlans], [1, 10, 20, 99])


if __name__ == "__main__":
    unittest.main()

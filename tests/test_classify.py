"""Telling network gear from end devices in real-world CDP/LLDP data.

The neighbors below are modelled on what Cisco/Arista switches actually report
for these devices (platform strings, system descriptions, capability codes).

    python -m unittest tests.test_classify -v
"""

from __future__ import annotations

import unittest

from switchscan.classify import AP, HOST, INFRA, PHONE, classify, classify_neighbor
from switchscan.scanner import should_crawl
from switchscan.ssh_collect import build_device
from switchscan.topology import build_topology

# name, platform, description, capabilities (as printed by the switch), expected
CASES = [
    # network gear
    ("dist1", "cisco WS-C3850-24T", "Cisco IOS Software, IOS-XE Software", "Router Switch IGMP", INFRA),
    ("old3560", "cisco WS-C3560CX-12PC-S", "Cisco IOS Software, C3560CX Software", "Switch IGMP", INFRA),
    ("nexus1", "N9K-C93180YC-EX", "Cisco Nexus Operating System (NX-OS) Software", "Router Switch", INFRA),
    ("leaf1", "", "Arista Networks EOS version 4.31.2F running on an Arista DCS-7050SX3", "", INFRA),
    ("cx6300", "", "Aruba JL659A 6300M 48SR5 CL6 PoE Swch FL.10.13.1000", "B,R", INFRA),
    ("fw01", "FortiGate-100F", "FortiGate-100F v7.2.8", "Router", INFRA),
    ("pfsense", "", "pfSense 2.7.2 FreeBSD 14.0-CURRENT amd64", "Router", INFRA),
    ("cumulus1", "", "Cumulus Linux version 5.4.0 running on Mellanox", "B,R", INFRA),
    ("mystery", "", "Some vendor's switch firmware 1.2", "B", INFRA),
    # access points
    ("ap-lobby", "cisco C9120AXI-B", "Cisco AP Software, ap1g7", "Trans-Bridge Source-Route-Bridge", AP),
    ("ap-2", "", "Aruba AP-515 ArubaOS 8.10", "B,W", AP),
    ("mr46", "Meraki MR46 Cloud Managed AP", "", "B,W", AP),
    # phones
    ("SEP001122334455", "Cisco IP Phone 8845", "sip8845_65.14-1-1SR1-1", "Host Phone Two-port Mac Relay", PHONE),
    ("SEPA0B1C2D3E4F5", "", "", "", PHONE),
    ("poly1", "", "Polycom VVX 450 6.4.3", "B,T", PHONE),
    # host computers: the ones that used to get through
    ("esx01.corp.local", "VMware ESX", "Releasebuild-22380479", "Switch", HOST),
    ("esx02", "", "VMware ESXi 8.0.2 build-22380479 VMware, Inc.", "B", HOST),
    ("web01", "", "Ubuntu 22.04.4 LTS Linux 5.15.0-105-generic #115-Ubuntu SMP x86_64", "B,R", HOST),
    ("hv01", "", "Microsoft Windows Server 2022 Datacenter", "S", HOST),
    ("DESKTOP-4KQ9F2L", "", "", "", HOST),
    ("", "", "", "", HOST),  # bare LLDP: chassis and port ID only (docks, NIC drivers)
    ("printer3", "", "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153", "O", HOST),
    ("nas01", "", "Synology DS920+ DSM 7.2", "", HOST),
    ("cam-front", "", "AXIS P3265-LVE Network Camera 10.12.199", "", HOST),
]


def neighbors_from_cdp():
    rows = [{"local_interface": f"Gi1/0/{i}", "neighbor_name": name, "platform": platform,
             "neighbor_description": desc, "capabilities": caps, "neighbor_interface": "eth0",
             "mgmt_address": f"10.9.0.{i}"}
            for i, (name, platform, desc, caps, _) in enumerate(CASES, 1)]
    return build_device("10.9.0.254", {"version": [{"hostname": "core"}], "cdp": rows}).neighbors


class ClassifyTest(unittest.TestCase):
    def test_real_world_neighbors(self):
        for n, (name, platform, desc, caps, expected) in zip(neighbors_from_cdp(), CASES):
            with self.subTest(name=name or "(bare LLDP)", platform=platform or desc[:30]):
                self.assertEqual(classify_neighbor(n), expected)

    def test_hints_only_match_whole_words(self):
        # "sep" in "September", "ucs" in "products" must not count
        self.assertEqual(classify(["switch"], "", "Built September 2023 for all products"), INFRA)

    def test_default_topology_has_no_end_devices(self):
        dev = build_device("10.9.0.254", {"version": [{"hostname": "core"}], "cdp": [
            {"local_interface": f"Gi1/0/{i}", "neighbor_name": name, "platform": platform,
             "neighbor_description": desc, "capabilities": caps, "neighbor_interface": "eth0"}
            for i, (name, platform, desc, caps, _) in enumerate(CASES, 1)]})
        shown = {n.label for n in build_topology([dev]).nodes} - {"core"}
        expected = {name for name, *_, kind in CASES if kind in (INFRA, AP)}
        self.assertEqual(shown, expected)
        everything = {n.label for n in build_topology([dev], include_hosts=True).nodes}
        self.assertTrue({"esx01.corp.local", "web01", "DESKTOP-4KQ9F2L", "SEP001122334455"} <= everything)

    def test_crawl_only_logs_in_to_network_gear(self):
        crawled = {n.remote_name for n in neighbors_from_cdp() if should_crawl(n)}
        self.assertEqual(crawled, {name for name, *_, kind in CASES if kind == INFRA})
        self.assertNotIn("esx01.corp.local", crawled)  # advertises itself as a "Switch"


if __name__ == "__main__":
    unittest.main()

"""Crawling a mixed-vendor network over SSH with one login (no network access needed).

    python -m unittest tests.test_ssh_crawl -v
"""

from __future__ import annotations

import asyncio
import threading
import unittest

from switchscan.model import Neighbor
from switchscan.scanner import UNLIMITED, ScanOptions, crawl_address, guess_device_type, scan
from switchscan.ssh_collect import build_device


def cdp(local, name, ip, platform="", desc="", caps="Router Switch IGMP"):
    return {"local_interface": local, "neighbor_name": name, "mgmt_address": ip, "platform": platform,
            "neighbor_description": desc, "capabilities": caps, "neighbor_interface": "Gi0/1"}


# host -> (hostname, parsed command output). Mirrors what ntc-templates returns.
NETWORK = {
    "10.1.0.1": ("core1", {"cdp": [
        cdp("Te1/0/1", "dist-nx.corp.local", "10.1.0.2", "N9K-C93180YC-EX",
            "Cisco Nexus Operating System (NX-OS) Software, Version 10.2"),
        cdp("Te1/0/2", "aruba-sw", "10.1.0.3", "", "ArubaOS-CX 10.13", "Bridge Router"),
        cdp("Gi1/0/5", "SEP001122334455", "10.1.5.50", "Cisco IP Phone 8845", "", "Host Phone"),
        cdp("Gi1/0/6", "odd-mgmt", "0011.2233.4455", "cisco WS-C2960X", ""),
    ]}),
    "10.1.0.2": ("dist-nx", {"lldp": [
        cdp("Eth1/1", "core1", "10.1.0.1", "", "Cisco IOS Software, C3850", "B,R"),
        cdp("Eth1/10", "leaf1", "10.1.0.4", "", "Arista Networks EOS version 4.30.1F", "B,R"),
    ]}),
    "10.1.0.4": ("leaf1", {"lldp": [
        cdp("Ethernet1", "access1", "10.1.0.9", "", "", "B"),  # a bridge, but no platform details
        cdp("Ethernet2", "access2", "10.1.0.10", "", "", "B"),
    ]}),
    "10.1.0.9": ("access1", {}),
}


class FakeSsh:
    def __init__(self):
        self.calls: dict[str, str] = {}
        self.lock = threading.Lock()

    def __call__(self, host: str, device_type: str):
        with self.lock:
            self.calls[host] = device_type
        if host not in NETWORK:
            raise RuntimeError(f"Authentication to device failed.\nCommon causes ...")
        name, parsed = NETWORK[host]
        return build_device(host, {"version": [{"hostname": name}], **parsed})


def run(depth: int, max_devices: int = 50):
    fake = FakeSsh()
    opts = ScanOptions(ssh_device_type="cisco_ios", ssh_user="admin", ssh_password="pw",
                       depth=depth, max_devices=max_devices, ssh_collector=fake)
    return asyncio.run(scan(["10.1.0.1"], opts)), fake


class SshCrawlTest(unittest.TestCase):
    def test_crawls_every_switch_with_the_right_platform(self):
        topo, fake = run(UNLIMITED)
        self.assertEqual(fake.calls, {"10.1.0.1": "cisco_ios", "10.1.0.2": "cisco_nxos",
                                      "10.1.0.4": "arista_eos", "10.1.0.9": "arista_eos",
                                      "10.1.0.10": "arista_eos"})
        self.assertEqual([d.sys_name for d in topo.devices], ["core1", "dist-nx", "leaf1", "access1"])

    def test_phones_unsupported_vendors_and_bad_addresses_are_not_logged_into(self):
        topo, fake = run(UNLIMITED)
        self.assertNotIn("10.1.5.50", fake.calls)  # phone
        self.assertNotIn("10.1.0.3", fake.calls)   # Aruba: no SSH commands for it
        failures = {f["host"]: f["error"] for f in topo.failures}
        self.assertIn("not scanned: aruba-sw", failures["10.1.0.3"])
        self.assertEqual(failures["10.1.0.10"], "Authentication to device failed.")
        self.assertEqual(len(fake.calls), 5)

    def test_depth_and_max_devices_limit_the_crawl(self):
        _, fake = run(1)
        self.assertEqual(set(fake.calls), {"10.1.0.1", "10.1.0.2"})
        _, fake = run(UNLIMITED, max_devices=3)
        self.assertEqual(set(fake.calls), {"10.1.0.1", "10.1.0.2", "10.1.0.4"})

    def test_links_join_up_across_vendors(self):
        topo, _ = run(UNLIMITED)
        pairs = {frozenset((l.a, l.b)) for l in topo.links}
        self.assertIn(frozenset(("core1", "dist-nx")), pairs)
        self.assertIn(frozenset(("dist-nx", "leaf1")), pairs)


class GuessTest(unittest.TestCase):
    def guess(self, platform="", desc="", default="cisco_ios"):
        return guess_device_type(Neighbor("CDP", "Gi1", remote_platform=platform, remote_description=desc), default)

    def test_platforms(self):
        self.assertEqual(self.guess("N9K-C9336C-FX2"), "cisco_nxos")
        self.assertEqual(self.guess("", "Cisco Nexus Operating System (NX-OS) Software"), "cisco_nxos")
        self.assertEqual(self.guess("", "Arista Networks EOS version 4.31"), "arista_eos")
        self.assertEqual(self.guess("cisco C9300-48P", "Cisco IOS Software [Cupertino], IOS-XE"), "cisco_ios")
        self.assertEqual(self.guess("cisco C9300-48P", "IOS-XE", default="cisco_xe"), "cisco_xe")
        self.assertEqual(self.guess("cisco WS-C2960X", default="arista_eos"), "cisco_ios")
        self.assertEqual(self.guess("", "", default="arista_eos"), "arista_eos")
        self.assertIsNone(self.guess("", "Juniper Networks, Inc. ex4300 JUNOS"))
        self.assertIsNone(self.guess("Cisco Meraki MS250"))

    def test_crawl_address(self):
        n = lambda ip: Neighbor("LLDP", "x", remote_mgmt_ip=ip)
        self.assertEqual(crawl_address(n(" 10.0.0.5 ")), "10.0.0.5")
        for bad in ("", "0011.2233.4455", "127.0.0.1", "0.0.0.0", "fe80::1"):
            self.assertEqual(crawl_address(n(bad)), "", bad)


if __name__ == "__main__":
    unittest.main()

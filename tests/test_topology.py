"""Crawl + topology merge on the demo network (no network access needed)."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from switchscan.demo import demo_walker_factory
from switchscan.model import Device, Topology
from switchscan.report import run_folder, safe_name, write_reports, write_switch_folders
from switchscan.scanner import ScanOptions, scan
from switchscan.topology import is_host


class TopologyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        opts = ScanOptions(depth=2, walker_factory=demo_walker_factory())
        cls.topo = asyncio.run(scan(["10.0.99.1"], opts))
        opts = ScanOptions(depth=2, walker_factory=demo_walker_factory(), include_hosts=True)
        cls.hosts = asyncio.run(scan(["10.0.99.1"], opts))

    def test_crawls_switches_but_not_phones_or_aps(self):
        self.assertEqual(sorted(d.sys_name for d in self.topo.devices), ["access-sw1", "access-sw2", "core-sw1"])
        self.assertEqual(self.topo.failures, [])

    def test_links_deduplicated_across_sides_and_protocols(self):
        links = {(l.a, l.a_port, l.b, l.b_port): l.protocols for l in self.topo.links}
        self.assertEqual(len(links), 6)
        self.assertEqual(links[("core-sw1", "Ethernet2", "access-sw2", "Gi1/0/48")], ["LLDP", "CDP"])

    def test_host_computers_left_out_by_default(self):
        names = {n.label for n in self.topo.nodes}
        self.assertEqual(names, {"core-sw1", "access-sw1", "access-sw2", "fw01", "SEP001122334455",
                                 "ap-lobby", "SEP001122334466"})  # esx01/esx02 (servers) are not shown
        self.assertEqual(self.topo.endpoints, [])
        self.assertFalse(any(n.kind == "host" for n in self.topo.nodes))

    def test_hosts_option_adds_servers_and_pcs(self):
        names = {n.label for n in self.hosts.nodes}
        self.assertTrue({"esx01", "esx02"} <= names)  # LLDP hosts
        pc = next(n for n in self.hosts.nodes if n.label == "10.0.10.31")  # found in the MAC/ARP tables
        self.assertEqual(pc.kind, "host")
        link = next(l for l in self.hosts.links if pc.id in (l.a, l.b))
        self.assertEqual((link.a, link.a_port, link.protocols), ("access-sw2", "Gi1/0/2", ["MAC"]))
        # each host appears once, and phones/LLDP hosts aren't duplicated from their MAC
        self.assertEqual(len({n.id for n in self.hosts.nodes}), len(self.hosts.nodes))
        self.assertNotIn("00:11:22:33:44:55", names)
        self.assertNotIn("00:50:56:aa:00:01", names)

    def test_is_host(self):
        self.assertTrue(is_host(["station"]))
        self.assertTrue(is_host([], "VMware ESXi 8.0.2 build-22380479"))
        self.assertTrue(is_host(["bridge"], "Linux 6.1 Debian"))
        self.assertFalse(is_host(["station", "telephone"]))  # phone
        self.assertFalse(is_host(["bridge", "wlan-ap"], "Linux ap-lobby"))  # access point
        self.assertFalse(is_host(["router", "switch"], "Cisco IOS"))
        self.assertFalse(is_host([], "Arista Networks EOS"))
        self.assertFalse(is_host([]))

    def test_endpoints_resolve_to_access_ports(self):
        ep = {e.mac: e for e in self.hosts.endpoints}
        pc = ep["f8:75:a4:20:00:01"]
        self.assertEqual((pc.switch, pc.port, pc.ip, pc.edge), ("access-sw2", "Gi1/0/2", "10.0.10.31", True))
        phone = ep["00:11:22:33:44:55"]
        self.assertEqual((phone.switch, phone.port, phone.neighbor), ("access-sw1", "1/1/7", "SEP001122334455"))
        self.assertFalse(ep["e8:1c:ba:00:00:01"].edge)  # firewall: only seen on a router-facing port

    def test_reports_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {p.name for p in write_reports(self.topo, Path(tmp))}
            self.assertTrue({"topology.json", "topology.html", "topology.dot", "links.csv"} <= files)
            self.assertNotIn("endpoints.csv", files)  # no host computers unless asked for
            html = (Path(tmp) / "topology.html").read_text(encoding="utf-8")
            self.assertNotIn("/*__DATA__*/null", html)
        with tempfile.TemporaryDirectory() as tmp:
            files = {p.name for p in write_reports(self.hosts, Path(tmp))}
            self.assertIn("endpoints.csv", files)

    def test_run_folder_is_named_and_dated(self):
        with tempfile.TemporaryDirectory() as tmp:
            when = datetime(2026, 11, 24, 14, 30, 5)
            first = run_folder(Path(tmp), "HQ / Floor 2", when)
            self.assertEqual(first, Path(tmp) / "HQ _ Floor 2" / "2026-11-24_14-30-05")
            first.mkdir(parents=True)
            self.assertEqual(run_folder(Path(tmp), "HQ / Floor 2", when).name, "2026-11-24_14-30-05_2")

    def test_safe_name(self):
        self.assertEqual(safe_name('a<b>:c"d|e?*'), "a_b_c_d_e_")
        self.assertEqual(safe_name("  ..  "), "topology")
        self.assertEqual(safe_name("CON"), "CON_")

    def test_each_switch_gets_its_own_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_switch_folders(self.topo, out)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["access-sw1", "access-sw2", "core-sw1"])
            sw = out / "access-sw2"
            self.assertEqual({p.name for p in sw.iterdir()},
                             {"device.json", "ports.csv", "interfaces.csv", "neighbors.csv",
                              "mac_table.csv", "arp.csv", "vlans.csv"})
            dev = json.loads((sw / "device.json").read_text(encoding="utf-8"))
            self.assertEqual(dev["sys_name"], "access-sw2")
            self.assertIn("f8:75:a4:20:00:01", (sw / "mac_table.csv").read_text(encoding="utf-8"))

    def test_ssh_raw_output_saved_but_kept_out_of_topology_json(self):
        dev = Device(host="10.1.1.1", collected_via="ssh", sys_name="sw/1",
                     raw_output={"show version": "Cisco IOS ...", "show ip arp": "Protocol ..."})
        topo = Topology(devices=[dev], nodes=[], links=[])
        self.assertNotIn("raw_output", topo.to_dict()["devices"][0])
        with tempfile.TemporaryDirectory() as tmp:
            write_switch_folders(topo, Path(tmp))
            cli = Path(tmp) / "sw_1" / "cli"
            self.assertEqual((cli / "show_version.txt").read_text(encoding="utf-8"), "Cisco IOS ...")
            self.assertTrue((cli / "show_ip_arp.txt").exists())


if __name__ == "__main__":
    unittest.main()

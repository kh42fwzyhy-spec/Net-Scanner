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


class TopologyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        opts = ScanOptions(depth=2, walker_factory=demo_walker_factory())
        cls.topo = asyncio.run(scan(["10.0.99.1"], opts))

    def test_crawls_switches_but_not_phones_or_aps(self):
        self.assertEqual(sorted(d.sys_name for d in self.topo.devices), ["access-sw1", "access-sw2", "core-sw1"])
        self.assertEqual(self.topo.failures, [])

    def test_links_deduplicated_across_sides_and_protocols(self):
        links = {(l.a, l.a_port, l.b, l.b_port): l.protocols for l in self.topo.links}
        self.assertEqual(len(links), 8)
        self.assertEqual(links[("core-sw1", "Ethernet2", "access-sw2", "Gi1/0/48")], ["LLDP", "CDP"])

    def test_endpoints_resolve_to_access_ports(self):
        ep = {e.mac: e for e in self.topo.endpoints}
        pc = ep["f8:75:a4:20:00:01"]
        self.assertEqual((pc.switch, pc.port, pc.ip, pc.edge), ("access-sw2", "Gi1/0/2", "10.0.10.31", True))
        phone = ep["00:11:22:33:44:55"]
        self.assertEqual((phone.switch, phone.port, phone.neighbor), ("access-sw1", "1/1/7", "SEP001122334455"))
        self.assertFalse(ep["e8:1c:ba:00:00:01"].edge)  # firewall: only seen on a router-facing port

    def test_reports_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {p.name for p in write_reports(self.topo, Path(tmp))}
            self.assertTrue({"topology.json", "topology.html", "topology.dot", "endpoints.csv"} <= files)
            html = (Path(tmp) / "topology.html").read_text(encoding="utf-8")
            self.assertNotIn("/*__DATA__*/null", html)

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

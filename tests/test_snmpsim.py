"""End-to-end test of the real SNMP path against snmpsim.

The demo network is exported as .snmprec files, served by snmpsim on localhost,
scanned with the real pysnmp walker, and compared with the in-memory result.

    python -m unittest tests.test_snmpsim -v
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path

from switchscan.demo import build_demo_network, demo_walker_factory, write_snmprec
from switchscan.snmp import SnmpCredentials, SnmpWalker
from switchscan.snmp_collect import SnmpCollector


def _responder_exe() -> str | None:
    found = shutil.which("snmpsim-command-responder")
    if found:
        return found
    for scheme in (sysconfig.get_default_scheme(), f"{sys.platform == 'win32' and 'nt' or 'posix'}_user"):
        try:
            scripts = Path(sysconfig.get_path("scripts", scheme))
        except KeyError:
            continue
        for name in ("snmpsim-command-responder.exe", "snmpsim-command-responder"):
            if (scripts / name).exists():
                return str(scripts / name)
    return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _comparable(device) -> dict:
    d = asdict(device)
    d.pop("host")
    d.pop("errors")
    return d


@unittest.skipUnless(_responder_exe(), "snmpsim is not installed (pip install snmpsim pysmi)")
class SnmpSimTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="switchscan-test-"))
        cls.dirs = write_snmprec(cls.tmp / "data")
        cls.procs = {}
        cls.ports = {}
        for host, data_dir in cls.dirs.items():
            port = _free_port()
            proc = subprocess.Popen(
                [_responder_exe(), f"--data-dir={data_dir}", f"--agent-udpv4-endpoint=127.0.0.1:{port}",
                 "--logging-method=null", f"--cache-dir={cls.tmp / 'cache' / host}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            cls.procs[host], cls.ports[host] = proc, port
        time.sleep(4)  # snmpsim indexes the data files before answering
        for host, proc in cls.procs.items():
            if proc.poll() is not None:
                raise RuntimeError(f"snmpsim for {host} exited: {proc.stderr.read().decode()[-800:]}")

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs.values():
            proc.terminate()
            proc.wait(10)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _scan(self, host: str, creds: SnmpCredentials):
        async def run():
            walker = SnmpWalker("127.0.0.1", creds, port=self.ports[host], timeout=3, retries=2)
            try:
                return await SnmpCollector(walker, host).collect()
            finally:
                walker.close()

        return asyncio.run(run())

    def _expected(self, host: str):
        return asyncio.run(SnmpCollector(demo_walker_factory()(host), host).collect())

    def test_v2c_matches_in_memory_scan(self):
        for host in build_demo_network():
            with self.subTest(host=host):
                got = self._scan(host, SnmpCredentials(version="2c", community="public"))
                self.assertEqual(got.errors, [], got.errors)
                self.assertEqual(_comparable(got), _comparable(self._expected(host)))

    def test_cisco_per_vlan_mac_table(self):
        got = self._scan("10.0.99.3", SnmpCredentials(version="2c", community="public"))
        self.assertEqual(
            {(m.mac, m.port, m.vlan) for m in got.mac_table},
            {("f8:75:a4:20:00:01", "Gi1/0/2", 10), ("f8:75:a4:20:00:02", "Gi1/0/5", 10),
             ("00:11:22:33:44:66", "Gi1/0/6", 20), ("00:1c:73:00:01:00", "Gi1/0/48", 99)},
        )

    def test_v3_auth_priv(self):
        # snmpsim's built-in v3 user; the data file is chosen by context name.
        creds = SnmpCredentials(version="3", user="simulator", auth_protocol="md5", auth_key="auctoritas",
                                priv_protocol="des", priv_key="privatus", context="public")
        got = self._scan("10.0.99.1", creds)
        self.assertEqual(got.sys_name, "core-sw1")
        self.assertEqual(len(got.neighbors), 5)

    def test_v1(self):
        got = self._scan("10.0.99.2", SnmpCredentials(version="1", community="public"))
        self.assertEqual(got.sys_name, "access-sw1")
        self.assertEqual(len(got.neighbors), 3)

    def test_bad_community_fails_cleanly(self):
        from switchscan.snmp import SnmpError

        with self.assertRaises(SnmpError):
            self._scan("10.0.99.1", SnmpCredentials(version="2c", community="wrong"))


if __name__ == "__main__":
    unittest.main()

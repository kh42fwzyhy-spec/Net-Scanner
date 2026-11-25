"""SSH to older Cisco switches (SHA-1-only crypto, IOS 12.x commands).

Runs a fake old-IOS SSH server on localhost, so no switch is needed.

    python -m unittest tests.test_legacy_ssh -v
"""

from __future__ import annotations

import logging
import unittest

import paramiko

# The deliberately failing handshake makes paramiko's server thread log a traceback
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

from switchscan.legacy_ssh import KexGroup1SHA1, LegacyTransport, legacy_algorithms_used
from switchscan.ssh_collect import collect_ssh

try:
    from .fake_ios import PASSWORD, USER, FakeOldSwitch
except ImportError:  # run via "unittest discover -s tests", where tests/ isn't a package
    from fake_ios import PASSWORD, USER, FakeOldSwitch


def handshake(port: int, transport_factory=None) -> paramiko.Transport:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=USER, password=PASSWORD, look_for_keys=False,
                   allow_agent=False, timeout=10, transport_factory=transport_factory)
    return client


class LegacyHandshakeTest(unittest.TestCase):
    def test_plain_paramiko_cannot_connect(self):
        """The problem being solved: modern paramiko refuses old switches outright."""
        with FakeOldSwitch("diffie-hellman-group14-sha1") as sw:
            with self.assertRaises(paramiko.SSHException) as cm:
                handshake(sw.port)
            self.assertIn("Incompatible", str(cm.exception))

    def test_each_legacy_key_exchange(self):
        for kex in ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
                    "diffie-hellman-group1-sha1"):
            with self.subTest(kex=kex), FakeOldSwitch(kex) as sw:
                client = handshake(sw.port, LegacyTransport)
                t = client.get_transport()
                self.assertTrue(t.is_authenticated())
                self.assertEqual(legacy_algorithms_used(t), [kex, "ssh-rsa host key"])
                client.close()

    def test_modern_switch_still_gets_modern_crypto(self):
        class ModernServer(LegacyTransport):  # offers both, like a current IOS-XE switch
            _preferred_keys = ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")

        with FakeOldSwitch(transport_class=ModernServer) as sw:
            client = handshake(sw.port, LegacyTransport)
            t = client.get_transport()
            self.assertEqual(legacy_algorithms_used(t), [])
            self.assertEqual(t.host_key_type, "rsa-sha2-512")
            client.close()

    def test_group1_prime_is_the_rfc_2409_safe_prime(self):
        p = KexGroup1SHA1.P
        self.assertEqual(p.bit_length(), 1024)
        for n in (p, (p - 1) // 2):  # Miller-Rabin with fixed bases
            d, r = n - 1, 0
            while d % 2 == 0:
                d, r = d // 2, r + 1
            for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                x = pow(a, d, n)
                if x in (1, n - 1):
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    self.fail("not prime")


class OldSwitchCollectTest(unittest.TestCase):
    """Full collect_ssh (netmiko + parsing) against an IOS 12.2-style switch."""

    @classmethod
    def setUpClass(cls):
        with FakeOldSwitch("diffie-hellman-group1-sha1") as sw:
            port = sw.port
            cls.device = collect_ssh("127.0.0.1", "cisco_ios", USER, PASSWORD, port=port, timeout=10)
            cls.commands = list(sw.commands)

    def test_switch_data_collected(self):
        d = self.device
        self.assertEqual(d.sys_name, "sw3560")
        self.assertEqual([i.name for i in d.interfaces], ["Gi0/1", "Gi0/2", "Gi0/3"])
        n = d.neighbors[0]
        self.assertEqual((n.protocol, n.remote_name, n.remote_mgmt_ip, n.local_port),
                         ("CDP", "core1.corp.local", "10.1.0.1", "GigabitEthernet0/1"))
        self.assertEqual([v.id for v in d.vlans], [1, 10])

    def test_old_mac_table_command_is_used(self):
        self.assertIn("show mac address-table", self.commands)
        self.assertIn("show mac-address-table", self.commands)
        macs = {m.mac: (m.port, m.vlan, m.ip) for m in self.device.mac_table}
        self.assertEqual(macs["00:11:22:33:44:55"], ("Gi0/2", 10, "10.1.10.25"))
        self.assertIn("show mac-address-table", self.device.raw_output)

    def test_notes_about_legacy_ssh_and_lldp(self):
        errors = " | ".join(self.device.errors)
        self.assertIn("older SHA-1 SSH algorithms (diffie-hellman-group1-sha1, ssh-rsa host key)", errors)
        self.assertIn("LLDP is not enabled", errors)
        self.assertNotIn("show mac address-table", errors)  # the fallback worked, so no error


if __name__ == "__main__":
    unittest.main()

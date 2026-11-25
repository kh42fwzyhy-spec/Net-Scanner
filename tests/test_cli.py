"""Credential prompting in the CLI, driven with scripted answers.

    python -m unittest tests.test_cli -v
"""

from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from switchscan.cli import Prompter, build_options, parse_args, topology_name
from switchscan.model import Device, Topology


def scripted(answers: list[str], secrets: list[str]) -> tuple[Prompter, io.StringIO]:
    out = io.StringIO()
    a, s = iter(answers), iter(secrets)
    return Prompter(input_fn=lambda _: next(a), secret_fn=lambda _: next(s), out=out), out


ENV_KEYS = ("SWITCHSCAN_COMMUNITY", "SWITCHSCAN_AUTH_KEY", "SWITCHSCAN_PRIV_KEY",
            "SWITCHSCAN_SSH_PASSWORD", "SWITCHSCAN_ENABLE_SECRET")


class PromptTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {k: "" for k in ENV_KEYS})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_menu_then_v2c_community(self):
        p, out = scripted(["1"], ["s3cret"])
        opts, desc = build_options(parse_args(["10.0.0.1"]), p)
        self.assertEqual((opts.snmp.version, opts.snmp.community), ("2c", "s3cret"))
        self.assertIn("How should switchscan log in", out.getvalue())
        self.assertEqual(desc, "SNMPv2c")

    def test_v2c_blank_community_defaults_to_public(self):
        p, _ = scripted([""], [""])
        opts, _ = build_options(parse_args(["10.0.0.1"]), p)
        self.assertEqual(opts.snmp.community, "public")

    def test_v3_full_prompt_with_retry_on_short_passphrase(self):
        # method 2 = v3, user, auth proto sha256 (2), priv proto default (Enter)
        p, out = scripted(["2", "netops", "2", ""], ["short", "authpass123", "privpass123"])
        opts, desc = build_options(parse_args(["10.0.0.1"]), p)
        c = opts.snmp
        self.assertEqual((c.version, c.user, c.auth_protocol, c.auth_key, c.priv_protocol, c.priv_key),
                         ("3", "netops", "sha256", "authpass123", "aes", "privpass123"))
        self.assertIn("at least 8 characters", out.getvalue())
        self.assertIn("authPriv", desc)

    def test_v3_only_missing_pieces_are_prompted(self):
        p, _ = scripted([], ["authpass123", "privpass123"])
        opts, _ = build_options(
            parse_args(["10.0.0.1", "-v", "3", "-u", "netops", "--auth-proto", "sha", "--priv-proto", "aes256"]), p)
        self.assertEqual((opts.snmp.auth_key, opts.snmp.priv_protocol), ("authpass123", "aes256"))

    def test_ssh_prompt(self):
        # method 3 = ssh, platform 3 = nxos, username, then password + blank enable secret
        p, _ = scripted(["3", "3", "admin"], ["pw", ""])
        opts, desc = build_options(parse_args(["10.0.0.1"]), p)
        self.assertEqual((opts.ssh_device_type, opts.ssh_user, opts.ssh_password, opts.enable_secret),
                         ("cisco_nxos", "admin", "pw", ""))
        self.assertEqual(desc, "SSH (cisco_nxos) as admin")

    def test_invalid_choice_reprompts(self):
        p, out = scripted(["9", "x", "1"], ["pub"])
        opts, _ = build_options(parse_args(["10.0.0.1"]), p)
        self.assertEqual(opts.snmp.community, "pub")
        self.assertEqual(out.getvalue().count("not one of the choices"), 2)

    def test_flags_mean_no_prompts(self):
        p, _ = scripted([], [])  # any prompt would raise StopIteration
        opts, _ = build_options(parse_args(["10.0.0.1", "-c", "corp-ro"]), p)
        self.assertEqual(opts.snmp.community, "corp-ro")

    def test_environment_used_instead_of_prompt(self):
        p, _ = scripted([], [])
        with mock.patch.dict(os.environ, {"SWITCHSCAN_SSH_PASSWORD": "envpw"}):
            opts, _ = build_options(parse_args(["10.0.0.1", "--ssh", "cisco_ios", "--ssh-user", "a"]), p)
        self.assertEqual(opts.ssh_password, "envpw")

    def test_no_prompt_mode_uses_defaults_or_errors(self):
        opts, _ = build_options(parse_args(["10.0.0.1", "--no-prompt"]), None)
        self.assertEqual(opts.snmp.community, "public")
        with self.assertRaises(SystemExit):
            build_options(parse_args(["10.0.0.1", "-v", "3", "-u", "x"]), None)


class TopologyNameTest(unittest.TestCase):
    topo = Topology(devices=[Device(host="10.0.0.1", collected_via="snmp", sys_name="core-sw1")],
                    nodes=[], links=[])

    def test_prompt_after_scan(self):
        p, out = scripted(["HQ Campus"], [])
        self.assertEqual(topology_name(parse_args(["10.0.0.1"]), self.topo, p), "HQ Campus")
        self.assertIn("Name for this topology [core-sw1]", out.getvalue())

    def test_enter_uses_first_switch_name(self):
        p, _ = scripted([""], [])
        self.assertEqual(topology_name(parse_args(["10.0.0.1"]), self.topo, p), "core-sw1")

    def test_name_flag_or_no_prompt(self):
        p, _ = scripted([], [])
        self.assertEqual(topology_name(parse_args(["10.0.0.1", "-n", "Lab"]), self.topo, p), "Lab")
        self.assertEqual(topology_name(parse_args(["10.0.0.1"]), self.topo, None), "core-sw1")


if __name__ == "__main__":
    unittest.main()

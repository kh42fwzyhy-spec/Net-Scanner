"""Command-line entry point: ``switchscan`` / ``python -m switchscan``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
import webbrowser
from pathlib import Path
from typing import Callable

from .report import FORMATS, run_folder, switch_folder_names, write_reports, write_switch_folders
from .scanner import UNLIMITED, ScanOptions, scan
from .snmp import AUTH_PROTOCOLS, PRIV_PROTOCOLS, SnmpCredentials

SSH_DEVICE_TYPES = [
    ("cisco_ios", "Cisco IOS (including older Catalyst 2960, 3560, 3560-CX, 3750)"),
    ("cisco_xe", "Cisco IOS-XE"),
    ("cisco_nxos", "Cisco NX-OS"),
    ("arista_eos", "Arista EOS"),
]
METHODS = [
    ("snmpv2c", "SNMP v2c (community string)"),
    ("snmpv3", "SNMP v3 (user + passphrases)"),
    ("ssh", "SSH (CLI login)"),
    ("snmpv1", "SNMP v1"),
]
METHOD_LABELS = dict(METHODS)

EPILOG = """\
examples:
  switchscan --demo
  switchscan 10.0.99.1                               # prompts for how to connect
  switchscan 10.0.99.1 -c public --crawl            # scan every switch found via CDP/LLDP
  switchscan 10.0.99.1 -c public --depth 2          # crawl at most 2 hops
  switchscan 10.0.99.1 -c public --crawl --hosts    # also show servers/PCs on their ports
  switchscan 10.0.99.1 -v 3 -u netops --auth-proto sha256 --priv-proto aes
  switchscan 10.0.99.1 --ssh cisco_ios --ssh-user admin --crawl

Anything not given on the command line is prompted for before the scan starts
(passwords are hidden as you type). Use --no-prompt in scripts.

secrets can also come from environment variables:
  SWITCHSCAN_COMMUNITY, SWITCHSCAN_AUTH_KEY, SWITCHSCAN_PRIV_KEY,
  SWITCHSCAN_SSH_PASSWORD, SWITCHSCAN_ENABLE_SECRET
"""


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="switchscan",
        description="Scan network switches over SNMP or SSH and map their topology "
                    "(LLDP/CDP neighbors, interfaces, VLANs, MAC and ARP tables).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    p.add_argument("hosts", nargs="*", help="switch IP addresses or hostnames to scan")
    p.add_argument("--demo", action="store_true", help="scan a built-in simulated network (no switch needed)")
    p.add_argument("-o", "--out", default="scan-output",
                   help="base output directory (default: %(default)s); each run is saved in "
                        "OUT/<topology name>/<date_time>/")
    p.add_argument("-n", "--name", help="topology name (asked for after the scan if omitted)")
    p.add_argument("--format", default=",".join(FORMATS),
                   help=f"comma-separated output formats: {', '.join(FORMATS)} (default: all)")
    p.add_argument("--open", action="store_true", help="open the HTML report when done")
    c = p.add_mutually_exclusive_group()
    c.add_argument("--crawl", action="store_true",
                   help="find the other switches through CDP/LLDP and scan them all with the same "
                        "credentials (asked about interactively if no crawl option is given)")
    c.add_argument("--depth", type=int,
                   help="crawl only this many hops from the given hosts (0 = only the given hosts)")
    c.add_argument("--no-crawl", action="store_true", help="scan only the given hosts")
    hst = p.add_mutually_exclusive_group()
    hst.add_argument("--hosts", action="store_true", dest="include_hosts",
                     help="add host computers (servers and PCs) to the topology, each linked to the switch "
                          "port it is plugged into (off by default)")
    hst.add_argument("--no-hosts", action="store_true", help="leave host computers out without asking")
    p.add_argument("--max-devices", type=int, default=50,
                   help="never try more than this many switches in one scan (default: %(default)s)")
    p.add_argument("--no-mac", action="store_true", help="skip the MAC address table (faster on big switches)")
    p.add_argument("--no-prompt", action="store_true",
                   help="never prompt; use command-line options, environment variables and defaults only")

    s = p.add_argument_group("SNMP")
    s.add_argument("-v", "--snmp-version", choices=["1", "2c", "3"])
    s.add_argument("-c", "--community", help="v1/v2c community")
    s.add_argument("-u", "--user", help="SNMPv3 user name")
    s.add_argument("--auth-proto", choices=sorted(AUTH_PROTOCOLS))
    s.add_argument("--auth-key", help="SNMPv3 auth passphrase (prompted if omitted)")
    s.add_argument("--priv-proto", choices=sorted(PRIV_PROTOCOLS))
    s.add_argument("--priv-key", help="SNMPv3 privacy passphrase (prompted if omitted)")
    s.add_argument("--context", default="", help="SNMPv3 context name (rarely needed)")
    s.add_argument("--port", type=int, default=161)
    s.add_argument("--timeout", type=float, default=2.0, help="seconds per SNMP request")
    s.add_argument("--retries", type=int, default=1)

    h = p.add_argument_group("SSH")
    h.add_argument("--ssh", metavar="DEVICE_TYPE", choices=[k for k, _ in SSH_DEVICE_TYPES],
                   help="collect over SSH; device type: " + ", ".join(k for k, _ in SSH_DEVICE_TYPES))
    h.add_argument("--ssh-user", help="SSH user name")
    h.add_argument("--ssh-port", type=int, default=22)
    h.add_argument("--enable", action="store_true", help="enter enable mode (prompts for the enable secret)")
    args = p.parse_args(argv)
    if not args.demo and not args.hosts:
        p.error("give at least one host to scan, or use --demo")
    return args


class Prompter:
    """Interactive questions on the terminal. Prompts go to stderr; secrets are hidden."""

    def __init__(self, input_fn: Callable[[str], str] = input,
                 secret_fn: Callable[[str], str] = getpass.getpass, out=None):
        self._input = input_fn
        self._secret = secret_fn
        self._out = out or sys.stderr

    def _say(self, text: str) -> None:
        print(text, file=self._out, flush=True)

    def text(self, label: str, default: str = "", required: bool = True) -> str:
        suffix = f" [{default}]" if default else ""
        while True:
            self._out.write(f"{label}{suffix}: ")
            self._out.flush()
            value = self._input("").strip()
            if value or default or not required:
                return value or default
            self._say("  a value is required")

    def secret(self, label: str, default: str = "", min_len: int = 0, required: bool = True) -> str:
        suffix = " [press Enter for default]" if default else ""
        while True:
            value = self._secret(f"{label}{suffix}: ")
            if not value and default:
                return default
            if not value and not required:
                return ""
            if not value:
                self._say("  a value is required")
            elif len(value) < min_len:
                self._say(f"  must be at least {min_len} characters")
            else:
                return value

    def yes_no(self, label: str, default: bool = True) -> bool:
        while True:
            self._out.write(f"{label} [{'Y/n' if default else 'y/N'}]: ")
            self._out.flush()
            raw = self._input("").strip().lower()
            if not raw:
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            self._say("  answer y or n")

    def choice(self, label: str, options: list[tuple[str, str]], default: str) -> str:
        self._say(label)
        for i, (key, desc) in enumerate(options, 1):
            self._say(f"  {i}) {desc}" + ("  (default)" if key == default else ""))
        keys = [k for k, _ in options]
        while True:
            self._out.write(f"Choose 1-{len(options)} [{keys.index(default) + 1}]: ")
            self._out.flush()
            raw = self._input("").strip().lower()
            if not raw:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return keys[int(raw) - 1]
            if raw in keys:
                return raw
            self._say("  not one of the choices")


def _env(name: str) -> str:
    return os.environ.get(name, "")


def _method_from_args(args: argparse.Namespace) -> str | None:
    if args.ssh or args.ssh_user:
        return "ssh"
    if args.snmp_version:
        return {"1": "snmpv1", "2c": "snmpv2c", "3": "snmpv3"}[args.snmp_version]
    if args.user or args.auth_key or args.priv_key:
        return "snmpv3"
    if args.community or _env("SWITCHSCAN_COMMUNITY"):
        return "snmpv2c"
    return None


def gather_credentials(args: argparse.Namespace, opts: ScanOptions, prompter: Prompter | None) -> str:
    """Fill the credential fields of ``opts``. Prompts only for what is missing.

    ``prompter`` is None when prompting is disabled or there is no terminal; in
    that case missing values fall back to environment variables and defaults.
    Returns a one-line description of the method for the scan banner.
    """
    method = _method_from_args(args)
    if method is None:
        method = prompter.choice("How should switchscan log in to the switch?", METHODS, "snmpv2c") \
            if prompter else "snmpv2c"

    if method == "ssh":
        device_type = args.ssh or (prompter.choice("Switch platform:", SSH_DEVICE_TYPES, "cisco_ios")
                                   if prompter else "")
        if not device_type:
            raise SystemExit("SSH needs --ssh DEVICE_TYPE when prompting is off")
        user = args.ssh_user or (prompter.text("SSH username") if prompter else "")
        password = _env("SWITCHSCAN_SSH_PASSWORD")
        asked_password = not password and prompter is not None
        if asked_password:
            password = prompter.secret("SSH password")
        if not user or not password:
            raise SystemExit("SSH needs --ssh-user and SWITCHSCAN_SSH_PASSWORD when prompting is off")
        enable = _env("SWITCHSCAN_ENABLE_SECRET")
        if not enable and prompter and (args.enable or asked_password):
            if args.enable:
                enable = prompter.secret("Enable secret")
            else:  # only offered when we're already asking for the login
                enable = prompter.secret("Enable secret (press Enter if not needed)", required=False)
        elif args.enable and not enable:
            raise SystemExit("--enable needs SWITCHSCAN_ENABLE_SECRET when prompting is off")
        opts.ssh_device_type, opts.ssh_user, opts.ssh_password = device_type, user, password
        opts.ssh_port, opts.enable_secret = args.ssh_port, enable
        return f"SSH ({device_type}) as {user}"

    if method == "snmpv3":
        user = args.user or (prompter.text("SNMPv3 username") if prompter else "")
        if not user:
            raise SystemExit("SNMPv3 needs --user")
        auth_proto = args.auth_proto or (
            prompter.choice("SNMPv3 authentication protocol:",
                            [(k, k.upper()) for k in ("sha", "sha256", "sha384", "sha512", "sha224", "md5", "none")],
                            "sha") if prompter else "sha")
        auth_key = ""
        if auth_proto != "none":
            auth_key = args.auth_key or _env("SWITCHSCAN_AUTH_KEY") or (
                prompter.secret("SNMPv3 auth passphrase", min_len=8) if prompter else "")
            if not auth_key:
                raise SystemExit("SNMPv3 needs an auth passphrase (--auth-key or SWITCHSCAN_AUTH_KEY)")
        priv_proto = "none" if auth_proto == "none" else args.priv_proto or (
            prompter.choice("SNMPv3 privacy (encryption) protocol:",
                            [("aes", "AES-128"), ("aes192", "AES-192"), ("aes256", "AES-256"),
                             ("des", "DES"), ("none", "None (authNoPriv)")], "aes") if prompter else "aes")
        priv_key = ""
        if priv_proto != "none":
            priv_key = args.priv_key or _env("SWITCHSCAN_PRIV_KEY") or (
                prompter.secret("SNMPv3 privacy passphrase", min_len=8) if prompter else "")
            if not priv_key:
                raise SystemExit("SNMPv3 needs a privacy passphrase (--priv-key or SWITCHSCAN_PRIV_KEY)")
        opts.snmp = SnmpCredentials(version="3", user=user, context=args.context,
                                    auth_protocol=auth_proto, auth_key=auth_key,
                                    priv_protocol=priv_proto, priv_key=priv_key)
        level = "authPriv" if priv_key else ("authNoPriv" if auth_key else "noAuthNoPriv")
        return f"SNMPv3 as {user} ({level}, {auth_proto}/{priv_proto})"

    version = "1" if method == "snmpv1" else "2c"
    community = args.community or _env("SWITCHSCAN_COMMUNITY") or (
        prompter.secret("SNMP community string", default="public") if prompter else "public")
    opts.snmp = SnmpCredentials(version=version, community=community)
    return f"SNMPv{version}" + (" (community 'public')" if community == "public" else "")


def crawl_depth(args: argparse.Namespace, prompter: Prompter | None, method: str) -> int:
    """How far to follow neighbors: --depth, --crawl/--no-crawl, else ask (default yes)."""
    if args.depth is not None:
        return max(0, args.depth)
    if args.crawl:
        return UNLIMITED
    if args.no_crawl or prompter is None:
        return 0
    login = "SSH login" if method.startswith("SSH") else "SNMP credentials"
    print("", file=sys.stderr)
    crawl = prompter.yes_no(f"Find the other switches through CDP/LLDP and scan them with the same {login}?")
    return UNLIMITED if crawl else 0


def want_hosts(args: argparse.Namespace, prompter: Prompter | None) -> bool:
    """--hosts / --no-hosts, else ask (default no)."""
    if args.include_hosts or args.no_hosts or prompter is None:
        return args.include_hosts
    return prompter.yes_no("Add host computers (servers, PCs) to the topology?", default=False)


def describe_crawl(depth: int, max_devices: int) -> str:
    if depth < 0:
        return f", crawling to every switch found (up to {max_devices})"
    return f", following neighbors {depth} hop(s)" if depth else ""


def build_options(args: argparse.Namespace, prompter: Prompter | None = None) -> tuple[ScanOptions, str]:
    opts = ScanOptions(
        max_devices=args.max_devices, collect_macs=not args.no_mac,
        snmp_port=args.port, timeout=args.timeout, retries=args.retries,
        progress=lambda msg: print(msg, file=sys.stderr, flush=True),
    )
    if args.demo:
        from .demo import demo_walker_factory

        opts.walker_factory = demo_walker_factory()
        opts.depth = UNLIMITED if args.depth is None and not args.no_crawl else max(0, args.depth or 0)
        opts.include_hosts = args.include_hosts
        return opts, "simulated demo network"
    method = gather_credentials(args, opts, prompter)
    opts.depth = crawl_depth(args, prompter, method)
    opts.include_hosts = want_hosts(args, prompter)
    return opts, method


def topology_name(args: argparse.Namespace, topo, prompter: Prompter | None) -> str:
    """The name the run is saved under: --name, else asked for, else the first switch's name."""
    default = topo.devices[0].id if topo.devices else "topology"
    if args.name:
        return args.name
    if prompter is None:
        return default
    print("", file=sys.stderr)
    try:
        return prompter.text("Name for this topology", default=default)
    except (KeyboardInterrupt, EOFError):  # don't throw away a finished scan
        print(f"\nusing '{default}'", file=sys.stderr)
        return default


def main(argv=None) -> int:
    args = parse_args(argv)
    interactive = not args.no_prompt and sys.stdin.isatty()
    name_prompter = Prompter() if interactive else None
    prompter = name_prompter if not args.demo else None
    if prompter:
        print(f"Credentials for {', '.join(args.hosts)}", file=sys.stderr)
    try:
        opts, method = build_options(args, prompter)
    except (KeyboardInterrupt, EOFError):
        print("\ncancelled", file=sys.stderr)
        return 130

    hosts = args.hosts or (["10.0.99.1"] if args.demo else [])
    print(f"\nScanning {', '.join(hosts)} via {method}" + describe_crawl(opts.depth, opts.max_devices)
          + (", including host computers" if opts.include_hosts else "") + "\n",
          file=sys.stderr, flush=True)

    topo = asyncio.run(scan(hosts, opts))

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    bad = set(formats) - set(FORMATS)
    if bad:
        raise SystemExit(f"unknown format(s): {', '.join(sorted(bad))}")
    name = topology_name(args, topo, name_prompter)
    out_dir = run_folder(Path(args.out), name)
    written = write_reports(topo, out_dir, formats) + write_switch_folders(topo, out_dir)

    hosts_found = sum(1 for n in topo.nodes if n.kind == "host")
    print(f"\n{len(topo.devices)} switch(es) scanned, {len(topo.nodes)} nodes, {len(topo.links)} links"
          + (f" ({hosts_found} host computer(s) from the MAC tables)" if topo.include_hosts else ""))
    for link in topo.links:
        if "MAC" in link.protocols:
            continue  # host computers: listed in endpoints.csv rather than here
        print(f"  {link.a} {link.a_port}  <->  {link.b} {link.b_port}   [{'+'.join(link.protocols)}]")
    for f in topo.failures:
        if f["error"].startswith("not scanned:"):
            print(f"  skipped {f['host']}: {f['error'][len('not scanned: '):]}")
        else:
            print(f"  could not scan {f['host']}: {f['error']}")
    for d in topo.devices:
        for e in d.errors:
            print(f"  warning ({d.id}): {e}")
    print(f"\nsaved '{name}' to {out_dir}")
    for path in written:
        if path.parent == out_dir:
            print(f"  {path.name}")
    for folder in switch_folder_names(topo):
        print(f"  {folder}{os.sep}  (everything collected from this switch)")

    html = out_dir / "topology.html"
    if args.open and html.exists():
        webbrowser.open(html.resolve().as_uri())
    return 0 if topo.devices else 1


if __name__ == "__main__":
    sys.exit(main())

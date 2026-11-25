"""Scan one or more switches, optionally crawling to their LLDP/CDP neighbors.

Crawling logs in to every switch a scanned switch reports as a CDP/LLDP neighbor
(with a management address), using the same credentials, until no new switches
turn up, the hop limit is reached, or ``max_devices`` switches have been tried.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Callable

from .model import Device, Neighbor, Topology
from .snmp import SnmpCredentials, SnmpWalker, Walker
from .snmp_collect import SnmpCollector
from .topology import build_topology
from .util import norm_hostname

# Neighbors advertising one of these are network gear worth crawling into.
CRAWL_CAPS = {"bridge", "router", "switch"}
SKIP_CAPS = {"telephone", "phone", "station", "host", "wlan-ap"}
UNLIMITED = -1  # ScanOptions.depth: crawl until no new switches are found

# Vendors seen in CDP/LLDP that the SSH collector has no commands for.
UNSUPPORTED_SSH = ("meraki", "aruba", "procurve", "juniper", "junos", "extreme", "dell", "fortinet",
                   "fortigate", "palo alto", "pan-os", "ubiquiti", "unifi", "mikrotik", "brocade",
                   "ruckus", "huawei", "h3c", "comware", "netgear", "tp-link", "vmware", "linux",
                   "windows", "adaptive security appliance")


@dataclass
class ScanOptions:
    snmp: SnmpCredentials | None = None
    snmp_port: int = 161
    timeout: float = 2.0
    retries: int = 1
    ssh_device_type: str = ""
    ssh_user: str = ""
    ssh_password: str = ""
    ssh_port: int = 22
    enable_secret: str = ""
    depth: int = 0
    max_devices: int = 50
    concurrency: int = 8
    collect_macs: bool = True
    include_hosts: bool = False  # add servers/PCs (LLDP hosts and MAC/ARP endpoints) to the topology
    # Lets demo mode and tests swap in a fake SNMP walker / SSH collector.
    walker_factory: Callable[[str], Walker] | None = None
    ssh_collector: Callable[[str, str], Device] | None = None  # (host, device_type) -> Device
    progress: Callable[[str], None] = field(default=lambda msg: None)


def should_crawl(caps: list[str]) -> bool:
    # Phones and APs also advertise "bridge", so an endpoint capability wins.
    caps_set = set(caps)
    if caps_set & SKIP_CAPS:
        return False
    return not caps_set or bool(caps_set & CRAWL_CAPS) or "other" in caps_set


def crawl_address(n: Neighbor) -> str:
    """The neighbor's management IP, or "" if it didn't advertise a usable one."""
    try:
        ip = ipaddress.ip_address(n.remote_mgmt_ip.strip())
    except ValueError:  # missing, or a MAC address in the management-address field
        return ""
    return "" if ip.is_unspecified or ip.is_loopback or ip.is_link_local else str(ip)


def guess_device_type(n: Neighbor, default: str) -> str | None:
    """Pick the SSH platform for a neighbor from what it advertised over CDP/LLDP.

    Returns None for vendors the SSH collector can't read, and ``default`` (the
    seed switch's platform) when the neighbor gives nothing to go on.
    """
    text = f"{n.remote_platform} {n.remote_description}".lower()
    if any(v in text for v in UNSUPPORTED_SSH):
        return None
    if "nx-os" in text or "nexus" in text or "n9k-" in text or "n7k-" in text or "n5k-" in text:
        return "cisco_nxos"
    if "arista" in text or " eos" in f" {text}":
        return "arista_eos"
    # IOS and IOS-XE log in and parse the same way, so keep whichever the user chose
    if "ios-xe" in text or "ios xe" in text:
        return default if default in ("cisco_ios", "cisco_xe") else "cisco_xe"
    if "cisco" in text or "ios" in text:
        return default if default in ("cisco_ios", "cisco_xe") else "cisco_ios"
    return default


async def _scan_one(host: str, opts: ScanOptions, device_type: str = "") -> Device:
    if opts.ssh_device_type:
        device_type = device_type or opts.ssh_device_type
        if opts.ssh_collector:
            return await asyncio.to_thread(opts.ssh_collector, host, device_type)
        from .ssh_collect import collect_ssh

        return await asyncio.to_thread(
            collect_ssh, host, device_type, opts.ssh_user, opts.ssh_password,
            opts.ssh_port, opts.enable_secret, opts.collect_macs,
        )
    if opts.walker_factory:
        walker = opts.walker_factory(host)
        return await SnmpCollector(walker, host, opts.collect_macs).collect()
    walker = SnmpWalker(host, opts.snmp or SnmpCredentials(), opts.snmp_port, opts.timeout, opts.retries)
    try:
        await walker.open()
        return await SnmpCollector(walker, host, opts.collect_macs).collect()
    finally:
        walker.close()


async def scan(seeds: list[str], opts: ScanOptions) -> Topology:
    devices: list[Device] = []
    failures: list[dict] = []
    attempted: set[str] = set()
    known_names: set[str] = set()
    skipped: set[str] = set()
    sem = asyncio.Semaphore(opts.concurrency)
    max_level = opts.max_devices if opts.depth < 0 else opts.depth

    async def guarded(host: str, device_type: str) -> Device | Exception:
        async with sem:
            opts.progress(f"scanning {host}" + (f" ({device_type})" if device_type else "") + " ...")
            try:
                return await _scan_one(host, opts, device_type)
            except Exception as exc:  # report and keep going with the others
                return exc

    # host -> SSH device type ("" = use the one the user chose)
    frontier: dict[str, str] = {h: "" for h in seeds}
    for level in range(max_level + 1):
        room = max(0, opts.max_devices - len(attempted))
        batch = [h for h in frontier if h not in attempted]
        if len(batch) > room:
            opts.progress(f"  stopping at --max-devices {opts.max_devices}; "
                          f"not scanned: {', '.join(batch[room:])}")
            batch = batch[:room]
        if not batch:
            break
        if level:
            opts.progress(f"\ncrawl hop {level}: {len(batch)} new switch(es) found")
        attempted.update(batch)
        results = await asyncio.gather(*(guarded(h, frontier[h]) for h in batch))

        next_frontier: dict[str, str] = {}
        for host, result in zip(batch, results):
            if isinstance(result, Exception):
                msg = str(result).strip().splitlines()[0] if str(result).strip() else result.__class__.__name__
                failures.append({"host": host, "error": msg})
                opts.progress(f"  {host}: FAILED - {msg}")
                continue
            name = norm_hostname(result.sys_name)
            if name and name in known_names:
                opts.progress(f"  {host}: already scanned as {result.sys_name}, skipping")
                continue
            known_names.add(name)
            devices.append(result)
            opts.progress(
                f"  {host}: {result.sys_name or '?'} - {len(result.interfaces)} interfaces, "
                f"{len(result.neighbors)} neighbors, {len(result.mac_table)} MACs"
            )
            if level >= max_level:
                continue
            own_type = frontier[host] or opts.ssh_device_type
            for n in result.neighbors:
                ip = crawl_address(n)
                if (not ip or ip in attempted or ip in next_frontier or ip in skipped
                        or norm_hostname(n.remote_name) in known_names or not should_crawl(n.capabilities)):
                    continue
                device_type = ""
                if opts.ssh_device_type:
                    guessed = guess_device_type(n, own_type)
                    if guessed is None:
                        skipped.add(ip)
                        what = (n.remote_platform or n.remote_description).strip().splitlines()[0][:60]
                        failures.append({"host": ip, "error": f"not scanned: {n.remote_name} ({what}) "
                                                              "isn't a platform switchscan can read over SSH"})
                        opts.progress(f"  {ip}: {n.remote_name} - not scanned, unsupported platform ({what})")
                        continue
                    device_type = guessed
                next_frontier[ip] = device_type
        frontier = next_frontier

    return build_topology(devices, failures, include_hosts=opts.include_hosts)

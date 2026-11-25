"""Scan one or more switches, optionally crawling to their LLDP/CDP neighbors."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable

from .model import Device, Topology
from .snmp import SnmpCredentials, SnmpWalker, Walker
from .snmp_collect import SnmpCollector
from .topology import build_topology
from .util import norm_hostname

# Neighbors advertising one of these are network gear worth crawling into.
CRAWL_CAPS = {"bridge", "router", "switch"}
SKIP_CAPS = {"telephone", "phone", "station", "host", "wlan-ap"}


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
    # Lets demo mode and tests swap in a fake SNMP walker.
    walker_factory: Callable[[str], Walker] | None = None
    progress: Callable[[str], None] = field(default=lambda msg: None)


def should_crawl(caps: list[str]) -> bool:
    # Phones and APs also advertise "bridge", so an endpoint capability wins.
    caps_set = set(caps)
    if caps_set & SKIP_CAPS:
        return False
    return not caps_set or bool(caps_set & CRAWL_CAPS) or "other" in caps_set


async def _scan_one(host: str, opts: ScanOptions) -> Device:
    if opts.ssh_device_type:
        from .ssh_collect import collect_ssh

        return await asyncio.to_thread(
            collect_ssh, host, opts.ssh_device_type, opts.ssh_user, opts.ssh_password,
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
    sem = asyncio.Semaphore(opts.concurrency)

    async def guarded(host: str) -> Device | Exception:
        async with sem:
            opts.progress(f"scanning {host} ...")
            try:
                return await _scan_one(host, opts)
            except Exception as exc:  # report and keep going with the others
                return exc

    frontier = list(dict.fromkeys(seeds))
    for level in range(opts.depth + 1):
        batch = [h for h in frontier if h not in attempted][: max(0, opts.max_devices - len(attempted))]
        if not batch:
            break
        attempted.update(batch)
        results = await asyncio.gather(*(guarded(h) for h in batch))

        frontier = []
        for host, result in zip(batch, results):
            if isinstance(result, Exception):
                msg = str(result) or result.__class__.__name__
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
            if level < opts.depth:
                for n in result.neighbors:
                    if (n.remote_mgmt_ip and n.remote_mgmt_ip not in attempted
                            and norm_hostname(n.remote_name) not in known_names
                            and should_crawl(n.capabilities)):
                        frontier.append(n.remote_mgmt_ip)
        frontier = list(dict.fromkeys(frontier))

    return build_topology(devices, failures)

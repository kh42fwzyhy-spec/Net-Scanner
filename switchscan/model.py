"""Data model shared by the SNMP and SSH collectors and the report writers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class Interface:
    index: int | None
    name: str
    description: str = ""
    alias: str = ""
    type: str = ""
    speed_mbps: int | None = None
    admin_status: str = ""
    oper_status: str = ""
    mac: str = ""
    vlan: int | None = None


@dataclass
class Neighbor:
    protocol: str  # "LLDP" or "CDP"
    local_port: str
    remote_name: str = ""
    remote_port: str = ""
    remote_port_description: str = ""
    remote_chassis_id: str = ""
    remote_mgmt_ip: str = ""
    remote_platform: str = ""
    remote_description: str = ""
    capabilities: list[str] = field(default_factory=list)


@dataclass
class MacEntry:
    mac: str
    port: str
    vlan: int | None = None
    status: str = "learned"
    ip: str = ""  # filled from the ARP table when the switch knows it


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str = ""


@dataclass
class Vlan:
    id: int
    name: str = ""


@dataclass
class Device:
    host: str
    collected_via: str
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    uptime_seconds: int | None = None
    contact: str = ""
    location: str = ""
    chassis_id: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    mac_table: list[MacEntry] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # SSH only: CLI command -> raw output, saved to the switch's folder (not the topology JSON)
    raw_output: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def id(self) -> str:
        return self.sys_name or self.host


@dataclass
class Node:
    id: str
    label: str
    kind: str  # "scanned", "neighbor" (seen via LLDP/CDP) or "host" (found in the MAC/ARP tables)
    mgmt_ip: str = ""
    platform: str = ""
    capabilities: list[str] = field(default_factory=list)


@dataclass
class Link:
    a: str
    a_port: str
    b: str
    b_port: str
    protocols: list[str] = field(default_factory=list)


@dataclass
class Endpoint:
    """Where a MAC address is physically attached, resolved across all switches."""

    mac: str
    ip: str
    vlan: int | None
    switch: str
    port: str
    edge: bool  # False = only ever seen on uplinks, so the real port is beyond the scan
    neighbor: str = ""  # LLDP/CDP name on that port, e.g. a phone the PC sits behind


@dataclass
class Topology:
    devices: list[Device]
    nodes: list[Node]
    links: list[Link]
    endpoints: list[Endpoint] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)  # {"host": ..., "error": ...}
    include_hosts: bool = False  # host computers (servers/PCs) were added as nodes and endpoints
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict:
        data = asdict(self)
        for d in data["devices"]:
            d.pop("raw_output", None)
        return data

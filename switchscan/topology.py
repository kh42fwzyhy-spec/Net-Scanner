"""Merge per-device neighbor tables into one graph of nodes and links."""

from __future__ import annotations

from .classify import END_DEVICES, INFRA, classify, classify_neighbor, is_end_device
from .model import Device, Endpoint, Link, Node, Topology
from .util import natural_key, norm_hostname, norm_ifname


def is_host(capabilities: list[str], description: str = "", name: str = "") -> bool:
    """True for an end device (PC, server, printer, phone) rather than network gear."""
    return classify(capabilities, "", description, name) in END_DEVICES


def build_topology(devices: list[Device], failures: list[dict] | None = None,
                   include_hosts: bool = False) -> Topology:
    """Merge the scanned devices into nodes and links.

    End devices (PCs, servers, printers, phones; see :mod:`.classify`) are left
    out unless ``include_hosts`` is set. Then they are added both from LLDP/CDP
    and from the MAC/ARP tables (every device found on an access port).
    """
    nodes: dict[str, Node] = {}
    alias: dict[str, str] = {}  # any identifier (name, chassis, MAC, IP) -> node id

    def register(node_id: str, *keys: str) -> None:
        for k in keys:
            if k:
                alias.setdefault(k.lower(), node_id)

    for d in devices:
        node_id = d.id
        if node_id in nodes:  # two devices with the same sysName
            node_id = f"{d.id} ({d.host})"
        nodes[node_id] = Node(
            id=node_id, label=d.sys_name or d.host, kind="scanned",
            mgmt_ip=d.host, platform=d.sys_descr.splitlines()[0][:80] if d.sys_descr else "",
        )
        d._node_id = node_id  # type: ignore[attr-defined]
        register(node_id, norm_hostname(d.sys_name), d.host, d.chassis_id,
                 *(i.mac for i in d.interfaces))

    scanned_alias = dict(alias)  # before neighbor stubs are added

    def resolve(n) -> str:
        for key in (n.remote_chassis_id, norm_hostname(n.remote_name), n.remote_mgmt_ip):
            if key and key.lower() in alias:
                return alias[key.lower()]
        node_id = n.remote_name or n.remote_chassis_id or n.remote_mgmt_ip or "unknown"
        if node_id in nodes:
            node_id = f"{node_id} [{n.remote_chassis_id}]"
        nodes[node_id] = Node(
            id=node_id, label=(n.remote_name or n.remote_chassis_id or "?").split("(")[0],
            kind="neighbor", mgmt_ip=n.remote_mgmt_ip,
            platform=n.remote_platform or (n.remote_description.splitlines()[0][:80] if n.remote_description else ""),
            capabilities=list(n.capabilities),
        )
        register(node_id, n.remote_chassis_id, norm_hostname(n.remote_name), n.remote_mgmt_ip)
        return node_id

    links: dict[frozenset, Link] = {}
    for d in devices:
        a = d._node_id  # type: ignore[attr-defined]
        for n in d.neighbors:
            if not include_hosts and is_end_device(n):
                continue
            b = resolve(n)
            node = nodes[b]
            if node.kind == "neighbor":  # enrich stubs with whatever we learn
                node.mgmt_ip = node.mgmt_ip or n.remote_mgmt_ip
                node.platform = node.platform or n.remote_platform
                node.capabilities = sorted(set(node.capabilities) | set(n.capabilities))
            key = frozenset({(a, norm_ifname(n.local_port)), (b, norm_ifname(n.remote_port))})
            link = links.get(key)
            if link is None:
                link = links[key] = Link(a=a, a_port=n.local_port, b=b, b_port=n.remote_port)
            if n.protocol not in link.protocols:
                link.protocols.append(n.protocol)

    endpoints: list[Endpoint] = []
    if include_hosts:
        endpoints = locate_endpoints(devices, scanned_alias)
        for e in endpoints:
            if not e.edge or e.mac.lower() in alias or (e.ip and e.ip.lower() in alias):
                continue  # beyond the scan, or already on the diagram (a phone, an LLDP host, ...)
            switch = next(d._node_id for d in devices if d.id == e.switch)  # type: ignore[attr-defined]
            node_id = e.ip or e.mac
            if node_id in nodes:
                node_id = e.mac
            nodes[node_id] = Node(id=node_id, label=e.ip or e.mac, kind="host", mgmt_ip=e.ip,
                                  platform=f"MAC {e.mac}" + (f", VLAN {e.vlan}" if e.vlan is not None else ""))
            register(node_id, e.mac)
            links[frozenset({(switch, norm_ifname(e.port)), (node_id, "")})] = Link(
                a=switch, a_port=e.port, b=node_id, b_port="", protocols=["MAC"])

    for d in devices:
        del d._node_id  # type: ignore[attr-defined]
    return Topology(devices=devices, nodes=list(nodes.values()), links=list(links.values()),
                    endpoints=endpoints, failures=failures or [], include_hosts=include_hosts)


def locate_endpoints(devices: list[Device], alias: dict[str, str]) -> list[Endpoint]:
    """Find the access port for every learned MAC.

    A MAC is learned on every switch along the path to it. The real location is
    the port that does not lead to another switch (an "edge" port).
    """
    ip_by_mac = {a.mac: a.ip for d in devices for a in d.arp}
    switch_macs = {d.chassis_id for d in devices} | {i.mac for d in devices for i in d.interfaces}

    uplinks: set[tuple[str, str]] = set()
    port_neighbor: dict[tuple[str, str], str] = {}
    for d in devices:
        for n in d.neighbors:
            key = (d.id, norm_ifname(n.local_port))
            scanned = any(k and k.lower() in alias for k in (n.remote_chassis_id, norm_hostname(n.remote_name)))
            if scanned or classify_neighbor(n) == INFRA:
                uplinks.add(key)
            else:
                port_neighbor.setdefault(key, n.remote_name or n.remote_chassis_id)

    seen: dict[str, Endpoint] = {}
    for d in devices:
        for m in d.mac_table:
            if not m.ip:
                m.ip = ip_by_mac.get(m.mac, "")
            if m.mac in switch_macs:
                continue
            key = (d.id, norm_ifname(m.port))
            edge = key not in uplinks
            current = seen.get(m.mac)
            if current is None or (edge and not current.edge):
                seen[m.mac] = Endpoint(mac=m.mac, ip=m.ip, vlan=m.vlan, switch=d.id, port=m.port,
                                       edge=edge, neighbor=port_neighbor.get(key, ""))
    return sorted(seen.values(), key=lambda e: (not e.edge, e.switch, natural_key(e.port), e.mac))

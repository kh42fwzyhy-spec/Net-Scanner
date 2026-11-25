"""A simulated three-switch network, served through a fake SNMP walker.

Used by ``switchscan --demo`` and by the tests. The same data can be exported
as .snmprec files for snmpsim, so the real SNMP path can be tested end to end.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from . import oids
from .snmp import OidTuple, Rows, SnmpError, oid_tuple
from .snmp_collect import LLDP_CAPS

# snmprec type tags
INT, OCTETS, OID, IPADDR, GAUGE, TICKS = 2, 4, 6, 64, 66, 67


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


class SnmpData:
    """OID -> (tag, value) store for one SNMP context, with MIB-aware helpers."""

    def __init__(self) -> None:
        self.values: dict[OidTuple, tuple[int, object]] = {}

    def set(self, oid: str, tag: int, value, *index: int) -> None:
        self.values[oid_tuple(oid) + tuple(index)] = (tag, value)

    def system(self, name: str, descr: str, object_id: str, location: str = "") -> None:
        self.set(oids.SYS_DESCR, OCTETS, descr.encode())
        self.set(oids.SYS_OBJECT_ID, OID, object_id)
        self.set(oids.SYS_UPTIME, TICKS, 123456789)
        self.set(oids.SYS_CONTACT, OCTETS, b"netops@example.com")
        self.set(oids.SYS_NAME, OCTETS, name.encode())
        self.set(oids.SYS_LOCATION, OCTETS, location.encode())

    def iface(self, idx: int, name: str, descr: str, speed_mbps: int, up: bool = True,
              alias: str = "", if_type: int = 6, phys: str = "") -> None:
        self.set(oids.IF_DESCR, OCTETS, descr.encode(), idx)
        self.set(oids.IF_TYPE, INT, if_type, idx)
        self.set(oids.IF_SPEED, GAUGE, min(speed_mbps * 1_000_000, 4_294_967_295), idx)
        self.set(oids.IF_PHYS_ADDRESS, OCTETS, mac(phys) if phys else b"", idx)
        self.set(oids.IF_ADMIN_STATUS, INT, 1, idx)
        self.set(oids.IF_OPER_STATUS, INT, 1 if up else 2, idx)
        self.set(oids.IF_NAME, OCTETS, name.encode(), idx)
        self.set(oids.IF_HIGH_SPEED, GAUGE, speed_mbps, idx)
        self.set(oids.IF_ALIAS, OCTETS, alias.encode(), idx)

    def lldp_local(self, chassis_mac: str, ports: dict[int, str]) -> None:
        self.set(oids.LLDP + ".3.1.0", INT, 4)
        self.set(oids.LLDP_LOC_CHASSIS_ID, OCTETS, mac(chassis_mac), 0)
        for num, name in ports.items():
            self.set(oids.LLDP + ".3.7.1.2", INT, 5, num)
            self.set(oids.LLDP_LOC_PORT_ID, OCTETS, name.encode(), num)
            self.set(oids.LLDP_LOC_PORT_DESC, OCTETS, name.encode(), num)

    def lldp_remote(self, local_port_num: int, rem_index: int, sys_name: str, chassis_mac: str,
                    port_id: str | bytes, port_desc: str = "", mgmt_ip: str = "",
                    caps: tuple[str, ...] = (), sys_desc: str = "") -> None:
        idx = (0, local_port_num, rem_index)
        bits = 0
        for c in caps:
            bits |= 0x80 >> LLDP_CAPS.index(c)
        port_is_mac = isinstance(port_id, bytes)
        self.set(oids.LLDP_REM_CHASSIS_ID_SUBTYPE, INT, 4, *idx)
        self.set(oids.LLDP_REM_CHASSIS_ID, OCTETS, mac(chassis_mac), *idx)
        self.set(oids.LLDP_REM_PORT_ID_SUBTYPE, INT, 3 if port_is_mac else 5, *idx)
        self.set(oids.LLDP_REM_PORT_ID, OCTETS, port_id if port_is_mac else port_id.encode(), *idx)
        self.set(oids.LLDP_REM_PORT_DESC, OCTETS, port_desc.encode(), *idx)
        self.set(oids.LLDP_REM_SYS_NAME, OCTETS, sys_name.encode(), *idx)
        self.set(oids.LLDP_REM_SYS_DESC, OCTETS, sys_desc.encode(), *idx)
        self.set(oids.LLDP_REM + ".11", OCTETS, bytes([bits, 0]), *idx)
        self.set(oids.LLDP_REM_CAP_ENABLED, OCTETS, bytes([bits, 0]), *idx)
        if mgmt_ip:
            addr = ipaddress.IPv4Address(mgmt_ip).packed
            self.set(oids.LLDP_REM_MAN_ADDR_IF_SUBTYPE, INT, 2, *idx, 1, 4, *addr)

    def cdp(self, ifindex: int, dev_index: int, device_id: str, port: str, ip: str,
            platform: str, caps: int, version: str = "") -> None:
        idx = (ifindex, dev_index)
        self.set(oids.CDP_ADDRESS_TYPE, INT, 1, *idx)
        self.set(oids.CDP_ADDRESS, OCTETS, ipaddress.IPv4Address(ip).packed, *idx)
        self.set(oids.CDP_VERSION, OCTETS, version.encode(), *idx)
        self.set(oids.CDP_DEVICE_ID, OCTETS, device_id.encode(), *idx)
        self.set(oids.CDP_DEVICE_PORT, OCTETS, port.encode(), *idx)
        self.set(oids.CDP_PLATFORM, OCTETS, platform.encode(), *idx)
        self.set(oids.CDP_CAPABILITIES, OCTETS, caps.to_bytes(4, "big"), *idx)

    def base_ports(self, mapping: dict[int, int]) -> None:
        for base, ifindex in mapping.items():
            self.set(oids.BASE_PORT_IFINDEX, INT, ifindex, base)

    def q_vlan(self, vid: int, name: str) -> None:
        self.set(oids.Q_VLAN_STATIC_NAME, OCTETS, name.encode(), vid)

    def q_pvid(self, base_port: int, vid: int) -> None:
        self.set(oids.Q_PVID, GAUGE, vid, base_port)

    def q_mac(self, vid: int, mac_text: str, base_port: int, status: int = 3) -> None:
        m = tuple(mac(mac_text))
        self.set(oids.Q_TP_FDB_PORT, INT, base_port, vid, *m)
        self.set(oids.Q_TP_FDB_STATUS, INT, status, vid, *m)

    def bridge_mac(self, mac_text: str, base_port: int, status: int = 3) -> None:
        m = tuple(mac(mac_text))
        self.set(oids.TP_FDB_PORT, INT, base_port, *m)
        self.set(oids.TP_FDB_STATUS, INT, status, *m)

    def arp(self, ifindex: int, ip: str, mac_text: str) -> None:
        self.set(oids.IP_NET_TO_MEDIA_PHYS, OCTETS, mac(mac_text), ifindex,
                 *ipaddress.IPv4Address(ip).packed)

    # -- consumers --------------------------------------------------------
    def walk(self, oid: str) -> Rows:
        root = oid_tuple(oid)
        rows: Rows = []
        for key in sorted(self.values):
            if key[: len(root)] == root:
                tag, value = self.values[key]
                rows.append((key, value if tag != OID else str(value)))
        return rows

    def to_snmprec(self) -> str:
        lines = []
        for key in sorted(self.values):
            tag, value = self.values[key]
            oid = ".".join(map(str, key))
            if tag == OCTETS:
                lines.append(f"{oid}|4x|{bytes(value).hex()}")
            else:
                lines.append(f"{oid}|{tag}|{value}")
        return "\n".join(lines) + "\n"


class FakeWalker:
    """Implements the Walker protocol over SnmpData (per-VLAN contexts supported)."""

    def __init__(self, contexts: dict[int | None, SnmpData]):
        self.contexts = contexts

    async def walk(self, oid: str, vlan: int | None = None) -> Rows:
        data = self.contexts.get(vlan)
        if data is None:
            raise SnmpError(f"no response for vlan context {vlan}")
        return data.walk(oid)


def build_demo_network() -> dict[str, dict[int | None, SnmpData]]:
    """host -> {vlan context (None = default) -> SnmpData}."""
    net: dict[str, dict[int | None, SnmpData]] = {}

    # ---- core-sw1: Arista-style core, Q-BRIDGE MIB, L3 for all VLANs --------
    core = SnmpData()
    core.system("core-sw1", "Arista Networks EOS version 4.31.2F running on an Arista DCS-7050SX3-48YC8",
                "1.3.6.1.4.1.30065.1.3011.7050.3741.48", "DC1 Row A Rack 3")
    core_ports = {}
    for i in range(1, 9):
        alias = {1: "uplink access-sw1", 2: "uplink access-sw2", 5: "esx01 vmnic0", 6: "esx02 vmnic0",
                 7: "fw01 inside"}.get(i, "")
        core.iface(i, f"Ethernet{i}", f"Ethernet{i}", 10000, up=i in (1, 2, 5, 6, 7), alias=alias,
                   phys=f"00:1c:73:00:00:0{i}")
        core_ports[i] = f"Ethernet{i}"
    core.iface(1000001, "Management1", "Management1", 1000, phys="00:1c:73:00:00:99")
    for vid in (10, 20, 30, 99):
        core.iface(5000 + vid, f"Vlan{vid}", f"Vlan{vid}", 0, if_type=136, phys="00:1c:73:00:01:00")
    core.lldp_local("00:1c:73:00:00:00", core_ports)
    core.lldp_remote(1, 1, "access-sw1", "a0:b1:c2:00:00:00", "1/1/49", "uplink to core",
                     "10.0.99.2", ("bridge", "router"), "Aruba JL659A 6300M 48SR5 CL6 PoE")
    core.lldp_remote(2, 1, "access-sw2.corp.local", "70:6b:b9:00:00:00", "Gi1/0/48",
                     "GigabitEthernet1/0/48", "10.0.99.3", ("bridge",), "Cisco IOS Software, C9200L")
    core.lldp_remote(5, 1, "esx01", "00:50:56:aa:00:01", mac("00:50:56:aa:00:01"), "vmnic0",
                     "", ("station",), "VMware ESXi 8.0")
    core.lldp_remote(6, 1, "esx02", "00:50:56:aa:00:02", mac("00:50:56:aa:00:02"), "vmnic0",
                     "", ("station",), "VMware ESXi 8.0")
    core.lldp_remote(7, 1, "fw01", "e8:1c:ba:00:00:01", "port1", "inside", "",
                     ("router",), "FortiGate-100F")
    core.base_ports({i: i for i in range(1, 9)})
    for vid, name in ((1, "default"), (10, "Users"), (20, "Voice"), (30, "Servers"), (99, "Mgmt")):
        core.q_vlan(vid, name)
    for port, vid in ((1, 99), (2, 99), (5, 30), (6, 30), (7, 99)):
        core.q_pvid(port, vid)
    core.q_mac(30, "00:50:56:aa:00:01", 5)
    core.q_mac(30, "00:50:56:aa:00:02", 6)
    core.q_mac(30, "00:50:56:9a:10:11", 5)
    core.q_mac(30, "00:50:56:9a:10:12", 6)
    core.q_mac(99, "e8:1c:ba:00:00:01", 7)
    core.q_mac(99, "a0:b1:c2:00:00:00", 1)
    core.q_mac(99, "70:6b:b9:00:00:00", 2)
    core.q_mac(99, "00:1c:73:00:01:00", 0, status=4)  # self entry - should be ignored
    for vid, port, host_mac in ((10, 1, "3c:22:fb:10:00:01"), (10, 1, "3c:22:fb:10:00:02"),
                                (20, 1, "00:11:22:33:44:55"), (10, 2, "f8:75:a4:20:00:01"),
                                (10, 2, "f8:75:a4:20:00:02"), (20, 2, "00:11:22:33:44:66")):
        core.q_mac(vid, host_mac, port)
    for ifidx, ip, m in ((5099, "10.0.99.2", "a0:b1:c2:00:00:00"), (5099, "10.0.99.3", "70:6b:b9:00:00:00"),
                         (5099, "10.0.99.254", "e8:1c:ba:00:00:01"), (5030, "10.0.30.11", "00:50:56:9a:10:11"),
                         (5030, "10.0.30.12", "00:50:56:9a:10:12"), (5010, "10.0.10.21", "3c:22:fb:10:00:01"),
                         (5010, "10.0.10.22", "3c:22:fb:10:00:02"), (5010, "10.0.10.31", "f8:75:a4:20:00:01"),
                         (5010, "10.0.10.32", "f8:75:a4:20:00:02"), (5020, "10.0.20.11", "00:11:22:33:44:55"),
                         (5020, "10.0.20.12", "00:11:22:33:44:66")):
        core.arp(ifidx, ip, m)
    net["10.0.99.1"] = {None: core}

    # ---- access-sw1: Aruba-style, LLDP port numbers differ from ifIndex -----
    a1 = SnmpData()
    a1.system("access-sw1", "Aruba JL659A 6300M 48SR5 CL6 PoE Swch FL.10.13.1000",
              "1.3.6.1.4.1.47196.4.1.1.1.302", "Bldg 2 IDF 1")
    a1_ports = {}
    for n in range(1, 13):
        a1.iface(100 + n, f"1/1/{n}", f"1/1/{n}", 1000, up=n in (3, 4, 7, 9))
        a1_ports[n] = f"1/1/{n}"
    a1.iface(149, "1/1/49", "1/1/49", 10000, alias="uplink to core")
    a1_ports[49] = "1/1/49"
    a1.lldp_local("a0:b1:c2:00:00:00", a1_ports)
    a1.lldp_remote(49, 1, "core-sw1", "00:1c:73:00:00:00", "Ethernet1", "uplink access-sw1",
                   "10.0.99.1", ("bridge", "router"), "Arista Networks EOS")
    a1.lldp_remote(7, 1, "SEP001122334455", "00:11:22:33:44:55", mac("00:11:22:33:44:55"), "Port 1",
                   "10.0.20.11", ("bridge", "telephone"), "Cisco IP Phone 8845")
    a1.lldp_remote(9, 1, "ap-lobby", "b4:5d:50:00:00:01", mac("b4:5d:50:00:00:01"), "eth0",
                   "10.0.99.50", ("bridge", "wlan-ap"), "Aruba AP-515")
    a1.base_ports({n: 100 + n for n in range(1, 13)} | {49: 149})
    for vid, name in ((1, "default"), (10, "Users"), (20, "Voice"), (99, "Mgmt")):
        a1.q_vlan(vid, name)
    for n in (3, 4, 7):
        a1.q_pvid(n, 10)
    a1.q_pvid(9, 99)
    a1.q_pvid(49, 99)
    a1.q_mac(10, "3c:22:fb:10:00:01", 3)
    a1.q_mac(10, "3c:22:fb:10:00:02", 4)
    a1.q_mac(20, "00:11:22:33:44:55", 7)
    a1.q_mac(99, "b4:5d:50:00:00:01", 9)
    a1.q_mac(99, "00:1c:73:00:01:00", 49)
    a1.arp(149, "10.0.99.1", "00:1c:73:00:01:00")
    net["10.0.99.2"] = {None: a1}

    # ---- access-sw2: Cisco, CDP + LLDP, per-VLAN BRIDGE-MIB contexts --------
    a2 = SnmpData()
    a2.system("access-sw2", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), "
              "Version 17.9.4", "1.3.6.1.4.1.9.1.2734", "Bldg 2 IDF 2")
    for n in range(1, 49):
        a2.iface(n, f"Gi1/0/{n}", f"GigabitEthernet1/0/{n}", 1000, up=n in (2, 5, 6, 48),
                 alias="uplink to core" if n == 48 else "", phys=f"70:6b:b9:00:00:{n:02x}")
    a2.iface(100, "Vl99", "Vlan99", 1000, if_type=136, phys="70:6b:b9:00:00:00")
    a2.lldp_local("70:6b:b9:00:00:00", {n: f"Gi1/0/{n}" for n in range(1, 49)})
    a2.lldp_remote(48, 1, "core-sw1", "00:1c:73:00:00:00", "Ethernet2", "uplink access-sw2",
                   "10.0.99.1", ("bridge", "router"), "Arista Networks EOS")
    a2.cdp(48, 1, "core-sw1.corp.local", "Ethernet2", "10.0.99.1", "Arista DCS-7050SX3", 0x09)
    a2.cdp(6, 1, "SEP001122334466", "Port 1", "10.0.20.12", "Cisco IP Phone 8865", 0x90)
    # VTP VLAN list (index = management domain, vlan) and access VLANs.
    for vid, name in ((1, "default"), (10, "Users"), (20, "Voice"), (99, "Mgmt"), (1002, "fddi-default")):
        a2.set(oids.VTP_VLAN_STATE, INT, 1, 1, vid)
        a2.set(oids.VTP_VLAN_NAME, OCTETS, name.encode(), 1, vid)
    for n, vid in ((2, 10), (5, 10), (6, 10)):
        a2.set(oids.VM_VLAN, INT, vid, n)
    a2.arp(100, "10.0.99.1", "00:1c:73:00:01:00")
    contexts: dict[int | None, SnmpData] = {None: a2}
    per_vlan = {
        1: [],
        10: [("f8:75:a4:20:00:01", 2), ("f8:75:a4:20:00:02", 5)],
        20: [("00:11:22:33:44:66", 6)],
        99: [("00:1c:73:00:01:00", 48)],
    }
    for vid, entries in per_vlan.items():
        ctx = SnmpData()
        ctx.base_ports({n: n for n in range(1, 49)})
        for m, port in entries:
            ctx.bridge_mac(m, port)
        contexts[vid] = ctx
    net["10.0.99.3"] = contexts
    return net


def demo_walker_factory():
    net = build_demo_network()

    def factory(host: str) -> FakeWalker:
        if host not in net:
            raise SnmpError(f"{host}: no SNMP response (timeout)")
        return FakeWalker(net[host])

    return factory


def write_snmprec(directory: Path, community: str = "public") -> dict[str, Path]:
    """Write one snmpsim data directory per demo host. Returns host -> directory."""
    out = {}
    for host, contexts in build_demo_network().items():
        host_dir = directory / host.replace(".", "_")
        host_dir.mkdir(parents=True, exist_ok=True)
        for vlan, data in contexts.items():
            name = community if vlan is None else f"{community}@{vlan}"
            (host_dir / f"{name}.snmprec").write_text(data.to_snmprec(), encoding="utf-8")
        out[host] = host_dir
    return out

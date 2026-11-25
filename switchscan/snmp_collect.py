"""Collect topology data from one switch over SNMP and turn it into a Device."""

from __future__ import annotations

import asyncio

from . import oids
from .model import ArpEntry, Device, Interface, MacEntry, Neighbor, Vlan
from .snmp import OidTuple, Rows, SnmpError, Value, Walker, oid_tuple
from .util import fmt_mac, is_printable, natural_key, norm_ifname, octets_to_ip, to_text

IF_TYPES = {
    6: "ethernet",
    24: "loopback",
    53: "virtual",
    117: "ethernet",
    131: "tunnel",
    135: "l2vlan",
    136: "vlan",
    161: "lag",
}
IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
LLDP_CAPS = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"]
CDP_CAPS = {
    0x01: "router",
    0x02: "bridge",
    0x04: "source-route-bridge",
    0x08: "switch",
    0x10: "host",
    0x20: "igmp",
    0x40: "repeater",
    0x80: "phone",
    0x100: "remote-managed",
    0x400: "two-port-mac-relay",
}


def column(rows: Rows, base: str) -> dict[OidTuple, Value]:
    """Index-suffix -> value for every row under ``base``."""
    prefix = oid_tuple(base)
    n = len(prefix)
    return {oid[n:]: v for oid, v in rows if oid[:n] == prefix}


def _chassis_or_port_id(subtype: int | None, raw: Value, mac_subtype: int) -> str:
    """Render an LLDP chassis or port ID according to its subtype."""
    if isinstance(raw, (int, str)):
        return str(raw)
    if subtype == mac_subtype and len(raw) == 6:
        return fmt_mac(raw)
    if subtype in (5, 4) and len(raw) >= 5 and raw[0] in (1, 2):  # networkAddress
        ip = octets_to_ip(raw[1:])
        if ip:
            return ip
    if is_printable(raw):
        return to_text(raw)
    if len(raw) == 6:
        return fmt_mac(raw)
    return raw.hex()


def _lldp_caps(raw: Value) -> list[str]:
    if not isinstance(raw, bytes) or not raw:
        return []
    caps = []
    for bit, name in enumerate(LLDP_CAPS):
        byte, offset = divmod(bit, 8)
        if byte < len(raw) and raw[byte] & (0x80 >> offset):
            caps.append(name)
    return caps


def _cdp_caps(raw: Value) -> list[str]:
    if isinstance(raw, bytes):
        value = int.from_bytes(raw[:4], "big") if raw else 0
    elif isinstance(raw, int):
        value = raw
    else:
        return []
    return [name for bit, name in CDP_CAPS.items() if value & bit]


class SnmpCollector:
    def __init__(self, walker: Walker, host: str, collect_macs: bool = True):
        self.w = walker
        self.host = host
        self.collect_macs = collect_macs
        self.device = Device(host=host, collected_via="snmp")
        self.if_by_index: dict[int, Interface] = {}

    async def _walk(self, oid: str, vlan: int | None = None, required: bool = False) -> Rows:
        try:
            return await self.w.walk(oid, vlan=vlan)
        except SnmpError as exc:
            if required:
                raise
            self.device.errors.append(f"walk {oid}{f' (vlan {vlan})' if vlan else ''}: {exc}")
            return []

    async def _walk_many(self, *oid_list: str, vlan: int | None = None) -> Rows:
        results = await asyncio.gather(*(self._walk(o, vlan=vlan) for o in oid_list))
        return [row for rows in results for row in rows]

    async def collect(self) -> Device:
        await self._system()
        await self._interfaces()
        await self._lldp()
        await self._cdp()
        await self._vlans()
        await self._arp()
        if self.collect_macs:
            await self._mac_table()
        return self.device

    # --- system -----------------------------------------------------------
    async def _system(self) -> None:
        rows = await self._walk(oids.SYSTEM, required=True)
        if not rows:
            raise SnmpError(f"{self.host}: no response to system group (check community/credentials)")
        sysvals = {".".join(map(str, o)): v for o, v in rows}
        d = self.device
        d.sys_descr = to_text(sysvals.get(oids.SYS_DESCR))
        d.sys_object_id = str(sysvals.get(oids.SYS_OBJECT_ID, ""))
        d.sys_name = to_text(sysvals.get(oids.SYS_NAME))
        d.contact = to_text(sysvals.get(oids.SYS_CONTACT))
        d.location = to_text(sysvals.get(oids.SYS_LOCATION))
        uptime = sysvals.get(oids.SYS_UPTIME)
        d.uptime_seconds = uptime // 100 if isinstance(uptime, int) else None

    # --- interfaces -------------------------------------------------------
    async def _interfaces(self) -> None:
        rows = await self._walk_many(
            oids.IF_DESCR, oids.IF_TYPE, oids.IF_SPEED, oids.IF_PHYS_ADDRESS,
            oids.IF_ADMIN_STATUS, oids.IF_OPER_STATUS, oids.IF_NAME,
            oids.IF_HIGH_SPEED, oids.IF_ALIAS,
        )
        descr = column(rows, oids.IF_DESCR)
        types = column(rows, oids.IF_TYPE)
        speed = column(rows, oids.IF_SPEED)
        phys = column(rows, oids.IF_PHYS_ADDRESS)
        admin = column(rows, oids.IF_ADMIN_STATUS)
        oper = column(rows, oids.IF_OPER_STATUS)
        names = column(rows, oids.IF_NAME)
        high = column(rows, oids.IF_HIGH_SPEED)
        alias = column(rows, oids.IF_ALIAS)

        for idx in sorted(set(descr) | set(names)):
            i = idx[0]
            mbps = high.get(idx)
            if not mbps and isinstance(speed.get(idx), int):
                mbps = speed[idx] // 1_000_000
            iface = Interface(
                index=i,
                name=to_text(names.get(idx)) or to_text(descr.get(idx)) or f"if{i}",
                description=to_text(descr.get(idx)),
                alias=to_text(alias.get(idx)),
                type=IF_TYPES.get(types.get(idx), str(types.get(idx, ""))),
                speed_mbps=mbps or None,
                admin_status=IF_STATUS.get(admin.get(idx), ""),
                oper_status=IF_STATUS.get(oper.get(idx), ""),
                mac=fmt_mac(phys[idx]) if isinstance(phys.get(idx), bytes) else "",
            )
            self.if_by_index[i] = iface
            self.device.interfaces.append(iface)

    def _ifname(self, ifindex: int | None) -> str:
        if ifindex is None:
            return ""
        iface = self.if_by_index.get(ifindex)
        return iface.name if iface else f"ifIndex {ifindex}"

    # --- LLDP -------------------------------------------------------------
    async def _lldp(self) -> None:
        rows = await self._walk_many(
            oids.LLDP_LOC_CHASSIS_ID, oids.LLDP_LOC_PORT_ID, oids.LLDP_LOC_PORT_DESC,
            oids.LLDP_REM, oids.LLDP_REM_MAN_ADDR_IF_SUBTYPE,
        )
        if not rows:
            return
        loc_chassis = column(rows, oids.LLDP_LOC_CHASSIS_ID)
        if loc_chassis.get((0,)) is not None:
            self.device.chassis_id = _chassis_or_port_id(4, loc_chassis[(0,)], 4)

        # Map lldpLocPortNum -> local interface name. Port numbers often equal
        # ifIndex but not always, so prefer matching on the port ID / description.
        by_name: dict[str, str] = {}
        for iface in self.device.interfaces:
            for candidate in (iface.name, iface.description):
                if candidate:
                    by_name.setdefault(norm_ifname(candidate), iface.name)
        loc_id = column(rows, oids.LLDP_LOC_PORT_ID)
        loc_desc = column(rows, oids.LLDP_LOC_PORT_DESC)

        def local_port(port_num: int) -> str:
            for src in (loc_id, loc_desc):
                raw = src.get((port_num,))
                if isinstance(raw, bytes) and is_printable(raw):
                    hit = by_name.get(norm_ifname(to_text(raw)))
                    if hit:
                        return hit
            if port_num in self.if_by_index:
                return self.if_by_index[port_num].name
            raw = loc_desc.get((port_num,)) or loc_id.get((port_num,))
            return to_text(raw) if isinstance(raw, bytes) and is_printable(raw) else f"port {port_num}"

        mgmt: dict[OidTuple, str] = {}
        for idx in column(rows, oids.LLDP_REM_MAN_ADDR_IF_SUBTYPE):
            # index = timeMark, localPort, remIndex, addrSubtype, addrLen, addr...
            if len(idx) < 6:
                continue
            key, subtype, length, addr = idx[:3], idx[3], idx[4], bytes(idx[5:])
            if subtype in (1, 2) and len(addr) == length:
                ip = octets_to_ip(addr)
                if ip and (key not in mgmt or subtype == 1):  # prefer IPv4
                    mgmt[key] = ip

        cols = {
            name: column(rows, oid)
            for name, oid in {
                "cid_sub": oids.LLDP_REM_CHASSIS_ID_SUBTYPE,
                "cid": oids.LLDP_REM_CHASSIS_ID,
                "pid_sub": oids.LLDP_REM_PORT_ID_SUBTYPE,
                "pid": oids.LLDP_REM_PORT_ID,
                "pdesc": oids.LLDP_REM_PORT_DESC,
                "name": oids.LLDP_REM_SYS_NAME,
                "desc": oids.LLDP_REM_SYS_DESC,
                "caps": oids.LLDP_REM_CAP_ENABLED,
            }.items()
        }
        for key in sorted(cols["cid"]):
            if len(key) != 3:
                continue
            port_sub = cols["pid_sub"].get(key)
            port_id = _chassis_or_port_id(port_sub, cols["pid"].get(key, b""), 3)
            port_desc = to_text(cols["pdesc"].get(key))
            # Hosts often send their MAC as port ID; the description is friendlier.
            remote_port = port_desc if (port_sub == 3 and port_desc) else port_id
            self.device.neighbors.append(
                Neighbor(
                    protocol="LLDP",
                    local_port=local_port(key[1]),
                    remote_name=to_text(cols["name"].get(key)),
                    remote_port=remote_port,
                    remote_port_description=port_desc,
                    remote_chassis_id=_chassis_or_port_id(cols["cid_sub"].get(key), cols["cid"][key], 4),
                    remote_mgmt_ip=mgmt.get(key, ""),
                    remote_description=to_text(cols["desc"].get(key)),
                    capabilities=_lldp_caps(cols["caps"].get(key)),
                )
            )

    # --- CDP --------------------------------------------------------------
    async def _cdp(self) -> None:
        rows = await self._walk(oids.CDP_CACHE)
        if not rows:
            return
        addr_type = column(rows, oids.CDP_ADDRESS_TYPE)
        addr = column(rows, oids.CDP_ADDRESS)
        version = column(rows, oids.CDP_VERSION)
        dev_id = column(rows, oids.CDP_DEVICE_ID)
        dev_port = column(rows, oids.CDP_DEVICE_PORT)
        platform = column(rows, oids.CDP_PLATFORM)
        caps = column(rows, oids.CDP_CAPABILITIES)
        for key in sorted(dev_id):
            ip = ""
            if addr_type.get(key) == 1 and isinstance(addr.get(key), bytes):
                ip = octets_to_ip(addr[key])
            self.device.neighbors.append(
                Neighbor(
                    protocol="CDP",
                    local_port=self._ifname(key[0]),
                    remote_name=to_text(dev_id[key]),
                    remote_port=to_text(dev_port.get(key)),
                    remote_mgmt_ip=ip,
                    remote_platform=to_text(platform.get(key)),
                    remote_description=to_text(version.get(key)),
                    capabilities=_cdp_caps(caps.get(key)),
                )
            )

    # --- VLANs ------------------------------------------------------------
    def _is_cisco(self) -> bool:
        return self.device.sys_object_id.startswith(oids.CISCO_ENTERPRISE)

    async def _vlans(self) -> None:
        rows = await self._walk_many(oids.Q_VLAN_STATIC_NAME, oids.Q_PVID, oids.BASE_PORT_IFINDEX)
        names = column(rows, oids.Q_VLAN_STATIC_NAME)
        vlans = {idx[0]: to_text(v) for idx, v in names.items() if idx}

        base_to_if = {idx[0]: v for idx, v in column(rows, oids.BASE_PORT_IFINDEX).items() if isinstance(v, int)}
        for idx, pvid in column(rows, oids.Q_PVID).items():
            iface = self.if_by_index.get(base_to_if.get(idx[0], -1))
            if iface and isinstance(pvid, int):
                iface.vlan = pvid

        if self._is_cisco():
            cisco = await self._walk_many(oids.VTP_VLAN_STATE, oids.VTP_VLAN_NAME, oids.VM_VLAN)
            state = column(cisco, oids.VTP_VLAN_STATE)
            vtp_names = column(cisco, oids.VTP_VLAN_NAME)
            for idx, st in state.items():
                vid = idx[-1]
                if st == 1 and not 1002 <= vid <= 1005:
                    vlans.setdefault(vid, to_text(vtp_names.get(idx)))
            for idx, vid in column(cisco, oids.VM_VLAN).items():
                iface = self.if_by_index.get(idx[0])
                if iface and isinstance(vid, int):
                    iface.vlan = vid

        self.device.vlans = [Vlan(id=v, name=n) for v, n in sorted(vlans.items())]

    # --- ARP --------------------------------------------------------------
    async def _arp(self) -> None:
        rows = await self._walk(oids.IP_NET_TO_MEDIA_PHYS)
        for idx, mac in column(rows, oids.IP_NET_TO_MEDIA_PHYS).items():
            if len(idx) == 5 and isinstance(mac, bytes) and len(mac) == 6:
                self.device.arp.append(
                    ArpEntry(ip=".".join(map(str, idx[1:])), mac=fmt_mac(mac), interface=self._ifname(idx[0]))
                )
        if self.device.arp:
            return
        rows = await self._walk(oids.IP_NET_TO_PHYSICAL_PHYS)
        for idx, mac in column(rows, oids.IP_NET_TO_PHYSICAL_PHYS).items():
            # index = ifIndex, addrType, addrLen, addr...
            if len(idx) >= 4 and idx[1] == 1 and isinstance(mac, bytes) and len(mac) == 6:
                ip = octets_to_ip(bytes(idx[3:]))
                if ip:
                    self.device.arp.append(ArpEntry(ip=ip, mac=fmt_mac(mac), interface=self._ifname(idx[0])))

    # --- MAC address table -------------------------------------------------
    def _add_macs(self, rows: Rows, port_oid: str, status_oid: str, base_to_if: dict[int, int],
                  vlan: int | None, has_fdb_id: bool) -> None:
        status = column(rows, status_oid)
        for idx, base_port in column(rows, port_oid).items():
            if has_fdb_id:
                fdb, mac = idx[0], idx[1:]
            else:
                fdb, mac = vlan, idx
            st = status.get(idx)
            if len(mac) != 6 or not isinstance(base_port, int) or base_port == 0 or st == 4:
                continue  # 4 = "self": the switch's own MAC
            ifindex = base_to_if.get(base_port)
            self.device.mac_table.append(
                MacEntry(
                    mac=fmt_mac(bytes(mac)),
                    port=self._ifname(ifindex) if ifindex else f"bridge port {base_port}",
                    vlan=fdb,
                    status={3: "learned", 5: "static", 1: "other"}.get(st, "learned"),
                )
            )

    async def _mac_table(self) -> None:
        rows = await self._walk_many(oids.BASE_PORT_IFINDEX, oids.Q_TP_FDB_PORT, oids.Q_TP_FDB_STATUS)
        base_to_if = {idx[0]: v for idx, v in column(rows, oids.BASE_PORT_IFINDEX).items() if isinstance(v, int)}
        self._add_macs(rows, oids.Q_TP_FDB_PORT, oids.Q_TP_FDB_STATUS, base_to_if, None, True)

        if not self.device.mac_table and self._is_cisco() and self.device.vlans:
            # Cisco IOS keeps one BRIDGE-MIB instance per VLAN (community@vlan).
            sem = asyncio.Semaphore(4)

            async def per_vlan(vid: int) -> tuple[int, Rows]:
                async with sem:
                    return vid, await self._walk_many(
                        oids.BASE_PORT_IFINDEX, oids.TP_FDB_PORT, oids.TP_FDB_STATUS, vlan=vid
                    )

            for vid, vrows in await asyncio.gather(*(per_vlan(v.id) for v in self.device.vlans)):
                vbase = {i[0]: v for i, v in column(vrows, oids.BASE_PORT_IFINDEX).items() if isinstance(v, int)}
                self._add_macs(vrows, oids.TP_FDB_PORT, oids.TP_FDB_STATUS, vbase, vid, False)

        if not self.device.mac_table:
            rows = await self._walk_many(oids.TP_FDB_PORT, oids.TP_FDB_STATUS)
            self._add_macs(rows, oids.TP_FDB_PORT, oids.TP_FDB_STATUS, base_to_if, None, False)

        ip_by_mac = {a.mac: a.ip for a in self.device.arp}
        for entry in self.device.mac_table:
            entry.ip = ip_by_mac.get(entry.mac, "")
        self.device.mac_table.sort(key=lambda m: (natural_key(m.port), m.vlan or 0, m.mac))

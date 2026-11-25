"""Collect topology data over SSH (CLI scraping) when SNMP is unavailable.

Command output is parsed with the TextFSM templates from ntc-templates, so the
same field names are used regardless of whether the output came from a live
session or a saved capture.
"""

from __future__ import annotations

import re

from .model import ArpEntry, Device, Interface, MacEntry, Neighbor, Vlan
from .util import fmt_mac

# platform -> logical command -> CLI command. The CLI command must match an
# ntc-templates template name for that platform.
COMMANDS: dict[str, dict[str, str]] = {
    "cisco_ios": {
        "version": "show version",
        "interfaces": "show interfaces status",
        "lldp": "show lldp neighbors detail",
        "cdp": "show cdp neighbors detail",
        "mac": "show mac address-table",
        "arp": "show ip arp",
        "vlan": "show vlan",
    },
    "cisco_nxos": {
        "version": "show version",
        "interfaces": "show interface status",
        "lldp": "show lldp neighbors detail",
        "cdp": "show cdp neighbors detail",
        "mac": "show mac address-table",
        "arp": "show ip arp",
        "vlan": "show vlan",
    },
    "arista_eos": {
        "version": "show version",
        "interfaces": "show interfaces status",
        "lldp": "show lldp neighbors detail",
        "mac": "show mac address-table",
        "arp": "show ip arp",
        "vlan": "show vlan",
    },
}
# netmiko device types that share another platform's templates
PLATFORM_ALIASES = {"cisco_xe": "cisco_ios", "cisco_ios_telnet": "cisco_ios"}
# Tried in order when a switch rejects the command (older IOS 12.x syntax). The
# ntc-templates template for the first command also parses these.
COMMAND_FALLBACKS = {"show mac address-table": ("show mac-address-table",)}
# Output that means the command didn't run
REJECTED = ("% Invalid", "% Unknown", "% Ambiguous", "% Incomplete")


def template_platform(device_type: str) -> str:
    return PLATFORM_ALIASES.get(device_type, device_type)


def _get(row: dict, *keys: str) -> str:
    """First non-empty value among ``keys``; list values are joined."""
    for key in keys:
        val = row.get(key) or row.get(key.upper())
        if isinstance(val, list):
            val = ", ".join(v for v in val if v)
        if val:
            return str(val).strip()
    return ""


def _int(text: str) -> int | None:
    m = re.match(r"\d+", text or "")
    return int(m.group()) if m else None


def _caps(text: str) -> list[str]:
    mapping = {
        "b": "bridge", "r": "router", "t": "telephone", "w": "wlan-ap", "s": "station",
        "p": "repeater", "c": "docsis", "o": "other", "switch": "switch", "host": "host",
        "phone": "phone", "router": "router", "bridge": "bridge", "trans-bridge": "bridge",
    }
    out = []
    for token in re.split(r"[,\s]+", (text or "").strip().lower()):
        name = mapping.get(token)
        if name and name not in out:
            out.append(name)
    return out


def _speed(text: str) -> int | None:
    t = (text or "").lower().lstrip("a-")
    m = re.match(r"(\d+(?:\.\d+)?)\s*([gm]?)", t)
    if not m:
        return None
    value = float(m.group(1))
    return int(value * 1000) if m.group(2) == "g" else int(value)


def build_device(host: str, parsed: dict[str, list[dict]]) -> Device:
    """Build a Device from TextFSM-parsed command output (keys as in COMMANDS)."""
    d = Device(host=host, collected_via="ssh")

    for row in parsed.get("version", [])[:1]:
        d.sys_name = _get(row, "hostname")
        d.sys_descr = " ".join(
            x for x in (_get(row, "hardware", "platform", "model"),
                        _get(row, "version", "os", "image")) if x
        )
        d.chassis_id = fmt_mac(_get(row, "mac_address", "sys_mac")) if _get(row, "mac_address", "sys_mac") else ""

    for row in parsed.get("interfaces", []):
        status = _get(row, "status").lower()
        d.interfaces.append(
            Interface(
                index=None,
                name=_get(row, "port"),
                alias=_get(row, "name"),
                type=_get(row, "type"),
                speed_mbps=_speed(_get(row, "speed")),
                admin_status="down" if status in ("disabled", "sfpabsent", "xcvrabsen") else "up",
                oper_status="up" if status == "connected" else "down",
                vlan=_int(_get(row, "vlan_id")),
            )
        )

    for proto in ("lldp", "cdp"):
        for row in parsed.get(proto, []):
            d.neighbors.append(
                Neighbor(
                    protocol=proto.upper(),
                    local_port=_get(row, "local_interface"),
                    remote_name=_get(row, "neighbor_name"),
                    remote_port=_get(row, "neighbor_interface", "neighbor_port_id"),
                    remote_chassis_id=fmt_mac(_get(row, "chassis_id")) if _get(row, "chassis_id") else "",
                    remote_mgmt_ip=_get(row, "mgmt_address", "interface_ip"),
                    remote_platform=_get(row, "platform"),
                    remote_description=_get(row, "neighbor_description"),
                    capabilities=_caps(_get(row, "capabilities")),
                )
            )

    for row in parsed.get("arp", []):
        mac = _get(row, "mac_address")
        if mac and re.search(r"[0-9a-f]{4}", mac.lower()):
            d.arp.append(ArpEntry(ip=_get(row, "ip_address"), mac=fmt_mac(mac), interface=_get(row, "interface")))
    ip_by_mac = {a.mac: a.ip for a in d.arp}

    for row in parsed.get("mac", []):
        mac = fmt_mac(_get(row, "destination_address", "mac_address"))
        port = _get(row, "destination_port", "ports")
        if not mac or not port or port.lower() in ("cpu", "router", "switch", "sup-eth1(r)"):
            continue
        d.mac_table.append(
            MacEntry(
                mac=mac,
                port=port,
                vlan=_int(_get(row, "vlan_id")),
                status=_get(row, "type").lower() or "dynamic",
                ip=ip_by_mac.get(mac, ""),
            )
        )

    for row in parsed.get("vlan", []):
        vid = _int(_get(row, "vlan_id"))
        if vid is not None and not 1002 <= vid <= 1005:
            d.vlans.append(Vlan(id=vid, name=_get(row, "vlan_name")))

    return d


def collect_ssh(
    host: str,
    device_type: str,
    username: str,
    password: str,
    port: int = 22,
    enable_secret: str = "",
    collect_macs: bool = True,
    timeout: int = 20,
) -> Device:
    """Log in with netmiko, run the show commands and parse them.

    Works with older switches too (e.g. Catalyst 2960/3560/3560-CX/3750): their
    SHA-1-only SSH is handled by :mod:`.legacy_ssh`, timeouts allow for slow
    switch CPUs, and IOS 12.x command spellings are tried when needed.
    """
    from ntc_templates.parse import parse_output  # imported lazily: slow to load

    from .legacy_ssh import legacy_algorithms_used, netmiko_class

    platform = template_platform(device_type)
    if platform not in COMMANDS:
        raise ValueError(
            f"SSH collection supports {', '.join(sorted(COMMANDS))} (plus cisco_xe); got {device_type!r}"
        )
    params = dict(
        device_type=device_type, host=host, port=port, username=username, password=password,
        conn_timeout=timeout,
        banner_timeout=30,  # older switches take a while to generate DH keys
        auth_timeout=30,
        fast_cli=False,     # don't cut timing corners on slow switch CPUs
    )
    if enable_secret:
        params["secret"] = enable_secret

    parsed: dict[str, list[dict]] = {}
    raw_output: dict[str, str] = {}
    errors: list[str] = []
    with netmiko_class(device_type)(**params) as conn:
        legacy = legacy_algorithms_used(conn.remote_conn_pre.get_transport())
        if legacy:
            errors.append("connected with older SHA-1 SSH algorithms (" + ", ".join(legacy)
                          + "); the scan is fine, but this switch's SSH could use an upgrade")
        if enable_secret:
            conn.enable()
        prompt_name = (conn.base_prompt or "").strip()
        for key, command in COMMANDS[platform].items():
            if key == "mac" and not collect_macs:
                continue
            for attempt in (command, *COMMAND_FALLBACKS.get(command, ())):
                try:
                    raw = conn.send_command(attempt, read_timeout=120 if key == "mac" else 60)
                except Exception as exc:  # one failing command shouldn't stop the scan
                    errors.append(f"{attempt}: {exc}")
                    break
                raw_output[attempt] = raw
                first = raw.strip().splitlines()[0] if raw.strip() else "no output"
                if any(r in raw for r in REJECTED):
                    if attempt == (command, *COMMAND_FALLBACKS.get(command, ()))[-1]:
                        errors.append(f"{attempt}: {first}")
                    continue  # try the older spelling, if there is one
                if "not enabled" in raw.lower():  # e.g. "% LLDP is not enabled"
                    errors.append(f"{attempt}: {first}")
                    break
                try:
                    # parse with the template for the canonical command; it covers the fallbacks
                    parsed[key] = parse_output(platform=platform, command=command, data=raw)
                except Exception as exc:
                    errors.append(f"{attempt}: could not parse output ({exc})")
                break

    device = build_device(host, parsed)
    if not device.sys_name:  # Arista's "show version" has no hostname; the CLI prompt does
        device.sys_name = prompt_name
    device.errors.extend(errors)
    device.raw_output = raw_output
    return device

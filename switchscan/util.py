"""Small formatting and normalisation helpers."""

from __future__ import annotations

import ipaddress
import re


def fmt_mac(raw: bytes | str) -> str:
    """Return a MAC as aa:bb:cc:dd:ee:ff, from raw bytes or any common text form."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) != 6:
            return ""
        return ":".join(f"{b:02x}" for b in raw)
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", raw or "")
    if len(hexdigits) != 12:
        return (raw or "").strip()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2)).lower()


def to_text(raw: bytes | str | int | None) -> str:
    """Decode an SNMP OCTET STRING as text, stripping NULs and padding."""
    if raw is None:
        return ""
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str):
        return raw.strip()
    return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()


def is_printable(raw: bytes) -> bool:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() for ch in text)


def octets_to_ip(raw: bytes) -> str:
    try:
        if len(raw) in (4, 16):
            return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        pass
    return ""


# Long interface-name prefixes and their short forms, longest first so that
# e.g. "TenGigabitEthernet" wins over "GigabitEthernet".
_IF_PREFIXES = [
    ("hundredgigabitethernet", "hu"),
    ("hundredgige", "hu"),
    ("fortygigabitethernet", "fo"),
    ("twentyfivegige", "twe"),
    ("twentyfivegigabitethernet", "twe"),
    ("tengigabitethernet", "te"),
    ("tengige", "te"),
    ("gigabitethernet", "gi"),
    ("fastethernet", "fa"),
    ("ethernet", "et"),
    ("port-channel", "po"),
    ("portchannel", "po"),
    ("management", "ma"),
    ("vlan", "vl"),
]
_SHORT_PREFIXES = {"gi", "te", "fa", "fo", "hu", "twe", "et", "eth", "po", "ma", "vl", "mgmt"}


def norm_ifname(name: str) -> str:
    """Normalise an interface name so 'GigabitEthernet1/0/1' == 'Gi1/0/1'."""
    n = (name or "").strip().lower().replace(" ", "")
    for long, short in _IF_PREFIXES:
        if n.startswith(long):
            return short + n[len(long) :]
    m = re.match(r"([a-z-]+)(.*)", n)
    if m and m.group(1) in _SHORT_PREFIXES:
        prefix = {"eth": "et"}.get(m.group(1), m.group(1))
        return prefix + m.group(2)
    return n


def natural_key(text: str) -> list:
    """Sort key so that '1/1/9' comes before '1/1/49'."""
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", text or "")]


def norm_hostname(name: str) -> str:
    """Normalise a device name for matching (drop domain and CDP serial suffix)."""
    n = (name or "").strip().lower()
    n = re.sub(r"\(.*\)$", "", n)
    try:
        ipaddress.ip_address(n)
        return n
    except ValueError:
        return n.split(".")[0]

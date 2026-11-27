"""Decide what kind of device a CDP/LLDP neighbor is.

The capability flags a device advertises can't be trusted on their own:

* ESXi hosts advertise CDP/LLDP as a "Switch" (their virtual switch).
* Linux servers running lldpd usually advertise "Bridge, Router".
* PCs, docks and printers often send LLDP with no capabilities, or just "Other".
* Some switches (e.g. Arista over SSH) report no capabilities at all.

So the platform / OS description is checked first, and the flags are only a
fallback. Network operating systems are recognised before host operating
systems, because several of them are Linux or BSD underneath.
"""

from __future__ import annotations

import re

INFRA = "infrastructure"  # switch, router, firewall, unknown network gear
AP = "access point"
PHONE = "phone"
HOST = "host"  # server, PC, printer, ...

END_DEVICES = {PHONE, HOST}  # left off the topology unless --hosts

# Network operating systems / vendors; matched before the host hints below.
NETWORK_OS = (
    "cisco ios", "ios-xe", "ios xe", "nx-os", "nexus", "cisco adaptive security", "catalyst", "arista",
    "junos", "juniper", "aruba", "procurve", "arubaos", "comware", "h3c", "huawei vrp", "extremexos",
    "exos", "voss", "fortigate", "fortios", "fortiswitch", "pan-os", "palo alto", "sonicwall",
    "pfsense", "opnsense", "vyos", "routeros", "mikrotik", "edgeos", "edgeswitch", "unifi switch",
    "cumulus", "sonic", "dell emc networking", "os10", "ftos", "powerconnect", "brocade", "icx",
    "ruckus", "meraki ms", "meraki mx", "netgear", "tp-link", "zyxel", "allied telesis", "alcatel",
    "omniswitch", "mellanox", "onyx", "checkpoint", "gaia", "watchguard", "sophos", "barracuda",
    "f5", "big-ip", "citrix adc", "netscaler", "riverbed", "silver peak", "velocloud", "viptela",
)
AP_HINTS = ("access point", "aironet", "air-ap", "air-cap", "c9105", "c9115", "c9120", "c9130", "c9136",
            "meraki mr", "unifi ap", "uap-", "u6-", "aruba ap", "ap-5", "ap-3", "instant on ap",
            "ruckus r", "ruckus t", "mist ap", "wlan-ap")
PHONE_HINTS = ("ip phone", "cisco ip phone", "polycom", "poly", "yealink", "avaya", "mitel",
               "grandstream", "snom", "ata 19", "spa5", "spa3", "unify openscape", "ringcentral")
HOST_HINTS = (
    "vmware", "esxi", "vsphere", "linux", "ubuntu", "debian", "red hat", "rhel", "centos", "rocky",
    "alma", "suse", "fedora", "windows", "microsoft", "hyper-v", "macos", "mac os", "darwin", "freebsd",
    "proxmox", "nutanix", "truenas", "synology", "qnap", "netapp", "isilon", "pure storage",
    "ucs", "idrac", "ilo", "integrated lights-out", "ipmi", "printer", "laserjet", "officejet",
    "jetdirect", "ricoh", "xerox", "kyocera", "brother", "canon", "lexmark", "konica", "dock",
    "thunderbolt", "axis", "hikvision", "dahua", "camera", "chromebook", "raspberry",
)
HOST_NAME_PATTERNS = re.compile(r"^(desktop|laptop|win|pc|wks|ws)-|^(ip-\d)|\.local$", re.I)
PHONE_NAME_PATTERNS = re.compile(r"^(sep|ata|cipc)[0-9a-f]{12}", re.I)

PHONE_CAPS = {"telephone", "phone"}
HOST_CAPS = {"station", "host"}
INFRA_CAPS = {"router", "switch", "bridge", "repeater", "docsis"}


_PATTERNS: dict[tuple[str, ...], re.Pattern] = {}


def _has(text: str, hints: tuple[str, ...]) -> bool:
    """Any hint at the start of a word; hints of 4 characters or fewer must be whole words."""
    if hints not in _PATTERNS:
        parts = [re.escape(h) + (r"(?![a-z0-9])" if len(h.strip(" -")) <= 4 else "") for h in hints]
        _PATTERNS[hints] = re.compile(r"(?<![a-z0-9])(?:" + "|".join(parts) + ")")
    return bool(_PATTERNS[hints].search(text))


def classify(capabilities: list[str], platform: str = "", description: str = "", name: str = "") -> str:
    """Return INFRA, AP, PHONE or HOST for a neighbor."""
    caps = {c.lower() for c in capabilities}
    text = f" {platform} {description} ".lower()

    # 1. Unambiguous identity first: phones and APs (they also say "bridge").
    if caps & PHONE_CAPS or PHONE_NAME_PATTERNS.match(name) or _has(text, PHONE_HINTS[:2]):
        return PHONE
    if "wlan-ap" in caps or _has(text, AP_HINTS):
        return AP
    # 2. What the platform/OS text says beats the capability flags.
    if _has(text, NETWORK_OS):
        return INFRA
    if _has(text, PHONE_HINTS):
        return PHONE
    if _has(text, HOST_HINTS) or HOST_NAME_PATTERNS.search(name):
        return HOST
    # 3. Fall back to the flags.
    if caps & HOST_CAPS:
        return HOST
    if caps & INFRA_CAPS:
        return INFRA
    # 4. Nothing to go on: no flags and no description is how PCs, docks and
    #    printers usually look; real switches send a system description.
    if not text.strip() or caps == {"other"}:
        return HOST
    return INFRA


def classify_neighbor(n) -> str:
    return classify(n.capabilities, n.remote_platform, n.remote_description, n.remote_name)


def is_end_device(n) -> bool:
    """Phones, PCs, servers, printers: never crawled, and left off the topology unless --hosts."""
    return classify_neighbor(n) in END_DEVICES

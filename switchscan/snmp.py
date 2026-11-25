"""Thin async SNMP walker on top of pysnmp 7 (v1, v2c and v3)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
    walk_cmd,
)
from pysnmp.proto import rfc1902

OidTuple = tuple[int, ...]
Value = bytes | int | str
Rows = list[tuple[OidTuple, Value]]

AUTH_PROTOCOLS = {
    "none": usmNoAuthProtocol,
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
    "sha224": usmHMAC128SHA224AuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol,
    "sha384": usmHMAC256SHA384AuthProtocol,
    "sha512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS = {
    "none": usmNoPrivProtocol,
    "des": usmDESPrivProtocol,
    "aes": usmAesCfb128Protocol,
    "aes128": usmAesCfb128Protocol,
    "aes192": usmAesCfb192Protocol,
    "aes256": usmAesCfb256Protocol,
}


class SnmpError(Exception):
    pass


class Walker(Protocol):
    """Anything that can walk an OID subtree. The demo mode supplies a fake one."""

    async def walk(self, oid: str, vlan: int | None = None) -> Rows: ...


@dataclass
class SnmpCredentials:
    version: str = "2c"  # "1", "2c" or "3"
    community: str = "public"
    user: str = ""
    auth_protocol: str = "sha"
    auth_key: str = ""
    priv_protocol: str = "aes"
    priv_key: str = ""
    context: str = ""  # SNMPv3 context name (most switches use the empty default)


def oid_tuple(oid: str) -> OidTuple:
    return tuple(int(p) for p in oid.strip(".").split("."))


def _convert(value) -> Value:
    """Turn a pysnmp value into bytes / int / str."""
    if isinstance(value, rfc1902.IpAddress):
        return str(ipaddress.IPv4Address(bytes(value.asOctets())))
    if isinstance(value, rfc1902.OctetString):  # includes Bits and Opaque
        return bytes(value.asOctets())
    if isinstance(value, rfc1902.ObjectIdentifier):
        return ".".join(str(x) for x in value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


class SnmpWalker:
    """Walks subtrees on one device. Create it, then ``await walker.open()``."""

    def __init__(
        self,
        host: str,
        creds: SnmpCredentials,
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 1,
        max_repetitions: int = 25,
    ):
        self.host = host
        self.creds = creds
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.max_repetitions = max_repetitions
        self.engine = SnmpEngine()
        self._transport = None

    async def open(self) -> None:
        try:
            is_v6 = ipaddress.ip_address(self.host).version == 6
        except ValueError:
            is_v6 = False
        cls = Udp6TransportTarget if is_v6 else UdpTransportTarget
        self._transport = await cls.create(
            (self.host, self.port), timeout=self.timeout, retries=self.retries
        )

    def close(self) -> None:
        try:
            self.engine.close_dispatcher()
        except Exception:
            pass

    def _auth(self, vlan: int | None):
        c = self.creds
        if c.version == "3":
            auth = AUTH_PROTOCOLS[c.auth_protocol] if c.auth_key else usmNoAuthProtocol
            priv = PRIV_PROTOCOLS[c.priv_protocol] if c.priv_key else usmNoPrivProtocol
            return UsmUserData(
                c.user,
                authKey=c.auth_key or None,
                privKey=c.priv_key or None,
                authProtocol=auth,
                privProtocol=priv,
            )
        # Cisco exposes per-VLAN bridge tables through "community@vlan".
        community = f"{c.community}@{vlan}" if vlan is not None else c.community
        return CommunityData(community, mpModel=0 if c.version == "1" else 1)

    def _context(self, vlan: int | None) -> ContextData:
        # SNMPv3 equivalent of community@vlan on Cisco is context "vlan-<id>".
        if self.creds.version == "3" and vlan is not None:
            return ContextData(contextName=f"vlan-{vlan}")
        if self.creds.version == "3" and self.creds.context:
            return ContextData(contextName=self.creds.context)
        return ContextData()

    async def walk(self, oid: str, vlan: int | None = None) -> Rows:
        if self._transport is None:
            await self.open()
        root = oid_tuple(oid)
        args = (self.engine, self._auth(vlan), self._transport, self._context(vlan))
        obj = ObjectType(ObjectIdentity(oid))
        if self.creds.version == "1":
            gen = walk_cmd(*args, obj, lexicographicMode=False)
        else:
            gen = bulk_walk_cmd(*args, 0, self.max_repetitions, obj, lexicographicMode=False)

        rows: Rows = []
        async for err_ind, err_status, err_index, var_binds in gen:
            if err_ind:
                raise SnmpError(f"{self.host}: {err_ind}")
            if err_status:
                # noSuchName etc. just means the subtree isn't supported.
                break
            for name, value in var_binds:
                t = tuple(name)
                if t[: len(root)] != root:
                    return rows
                if value.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                    continue
                rows.append((t, _convert(value)))
        return rows

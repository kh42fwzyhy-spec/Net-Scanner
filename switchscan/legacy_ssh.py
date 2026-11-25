"""SSH to older switches whose crypto modern paramiko has dropped.

Catalyst 2960/3560/3750 (including the 3560-CX) and other IOS 12.x/15.x boxes
only offer SHA-1 key exchange (diffie-hellman-group14-sha1, -group-exchange-sha1,
-group1-sha1) and the SHA-1 ``ssh-rsa`` host key signature. Paramiko 4+ removed
all of these, so a plain connection fails with "Incompatible ssh peer".

:class:`LegacyTransport` puts them back *at the end* of the preference lists.
SSH uses the client's first choice that the server also supports, and the
algorithm negotiation is covered by the key-exchange hash, so a switch that
supports modern algorithms still gets modern ones; the SHA-1 options are only
used when a switch offers nothing newer.
"""

from __future__ import annotations

from hashlib import sha1

from cryptography.hazmat.primitives import hashes
from paramiko import Transport
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256
from paramiko.rsakey import RSAKey


class _RecordsLegacyKex:
    """Notes on the transport that a legacy key exchange was used."""

    def start_kex(self):
        self.transport.legacy_kex = self.name
        return super().start_kex()


class KexGroup14SHA1(_RecordsLegacyKex, KexGroup14SHA256):
    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class KexGroup1SHA1(_RecordsLegacyKex, KexGroup14SHA256):
    # RFC 2409 section 6.2, "Second Oakley Group" (1024-bit MODP)
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa: E501
    G = 2
    name = "diffie-hellman-group1-sha1"
    hash_algo = sha1


class KexGexSHA1(_RecordsLegacyKex, KexGexSHA256):
    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1


class LegacyRSAKey(RSAKey):
    """RSAKey that also accepts the SHA-1 ``ssh-rsa`` signature older switches send."""

    HASHES = {**RSAKey.HASHES, "ssh-rsa": hashes.SHA1}


LEGACY_KEX = (KexGroup14SHA1, KexGexSHA1, KexGroup1SHA1)
LEGACY_KEX_NAMES = tuple(k.name for k in LEGACY_KEX)


class LegacyTransport(Transport):
    """A paramiko Transport that can also talk to old IOS SSH servers."""

    _preferred_kex = Transport._preferred_kex + LEGACY_KEX_NAMES
    _kex_info = {**Transport._kex_info, **{k.name: k for k in LEGACY_KEX}}
    _preferred_keys = Transport._preferred_keys + ("ssh-rsa",)
    _key_info = {**Transport._key_info, "ssh-rsa": LegacyRSAKey}

    legacy_kex = ""  # set by a legacy Kex class when one is negotiated


def legacy_algorithms_used(transport) -> list[str]:
    """The SHA-1 algorithms a finished connection ended up using (empty if none)."""
    used = [getattr(transport, "legacy_kex", "")]
    if getattr(transport, "host_key_type", "") == "ssh-rsa":
        used.append("ssh-rsa host key")
    return [u for u in used if u]


_NETMIKO_CLASSES: dict[str, type] = {}


def netmiko_class(device_type: str) -> type:
    """netmiko's driver class for ``device_type``, made to connect with LegacyTransport."""
    if device_type not in _NETMIKO_CLASSES:
        from netmiko.ssh_dispatcher import CLASS_MAPPER

        base = CLASS_MAPPER[device_type]

        def _connect_params_dict(self):
            return {**base._connect_params_dict(self), "transport_factory": LegacyTransport}

        _NETMIKO_CLASSES[device_type] = type(f"Legacy{base.__name__}", (base,),
                                             {"_connect_params_dict": _connect_params_dict})
    return _NETMIKO_CLASSES[device_type]

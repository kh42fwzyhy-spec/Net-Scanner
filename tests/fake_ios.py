"""A tiny SSH server that behaves like an old Catalyst (IOS 12.2/15.x) for tests.

It offers only the algorithms such switches do (SHA-1 key exchange, the ssh-rsa
host key, CBC ciphers, hmac-sha1) and answers a few show commands the way IOS
does, including rejecting the newer ``show mac address-table`` spelling.
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading

import paramiko

from switchscan.legacy_ssh import KexGroup14SHA256, LegacyRSAKey, LegacyTransport

HOSTNAME = "sw3560"
USER, PASSWORD = "admin", "pw"

INVALID = "                         ^\r\n% Invalid input detected at '^' marker.\r\n"
RESPONSES = {
    "show version": f"""Cisco IOS Software, C3560CX Software (C3560CX-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
ROM: Bootstrap program is C3560CX boot loader
{HOSTNAME} uptime is 3 weeks, 2 days, 4 hours, 1 minute
System returned to ROM by power-on
System image file is "flash:c3560cx-universalk9-mz.152-7.E8.bin"
cisco WS-C3560CX-12PC-S (APM86XXX) processor (revision A0) with 524288K bytes of memory.
Base ethernet MAC Address       : 00:11:22:33:44:00
Configuration register is 0xF
""",
    "show interfaces status": """
Port      Name               Status       Vlan       Duplex  Speed Type
Gi0/1     uplink to core     connected    trunk        a-full a-1000 10/100/1000BaseTX
Gi0/2     desk 12            connected    10           a-full  a-100 10/100/1000BaseTX
Gi0/3                        notconnect   1              auto   auto 10/100/1000BaseTX
""",
    "show lldp neighbors detail": "% LLDP is not enabled\r\n",
    "show cdp neighbors detail": """-------------------------
Device ID: core1.corp.local
Entry address(es):
  IP address: 10.1.0.1
Platform: cisco WS-C3850-24T,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): TenGigabitEthernet1/0/1
Holdtime : 150 sec

Version :
Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4, RELEASE SOFTWARE (fc5)

advertisement version: 2
Native VLAN: 1
Duplex: full
Management address(es):
  IP address: 10.1.0.1

""",
    "show mac address-table": INVALID,  # IOS 12.1/12.2 only knows the hyphenated form
    "show mac-address-table": """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    0011.2233.4455    DYNAMIC     Gi0/2
   1    00aa.bbcc.0001    DYNAMIC     Gi0/1
Total Mac Addresses for this criterion: 3
""",
    "show ip arp": """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.10.25             12   0011.2233.4455  ARPA   Vlan10
""",
    "show vlan": """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/3
10   users                            active    Gi0/2
""",
    "terminal width 511": "",
    "terminal length 0": "",
}


def old_ios_transport(kex: str) -> type:
    """Server transport offering only what an old IOS switch offers."""

    class OldIosTransport(LegacyTransport):
        _preferred_kex = (kex,)
        _preferred_keys = ("ssh-rsa",)
        _preferred_ciphers = ("aes128-cbc", "3des-cbc")
        _preferred_macs = ("hmac-sha1",)

    return OldIosTransport


class _Server(paramiko.ServerInterface):
    def __init__(self):
        self.shell = threading.Event()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = (username, password) == (USER, PASSWORD)
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


def _moduli_file() -> str:
    """A one-entry moduli file so the server side can do group-exchange (uses the RFC 3526 2048-bit group)."""
    path = os.path.join(tempfile.mkdtemp(), "moduli")
    with open(path, "w") as fh:
        fh.write(f"20200101000000 2 6 100 2047 2 {KexGroup14SHA256.P:X}\n")
    return path


class FakeOldSwitch:
    """Serve SSH on 127.0.0.1 with the given key-exchange; use as a context manager."""

    def __init__(self, kex: str = "diffie-hellman-group1-sha1", transport_class: type | None = None):
        self.transport_class = transport_class or old_ios_transport(kex)
        self.host_key = LegacyRSAKey(key=paramiko.RSAKey.generate(1024).key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.negotiated: list[tuple[str, str]] = []  # (kex, host key type) per connection
        self.commands: list[str] = []
        self._moduli = _moduli_file()
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._stop = True
        self.sock.close()

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        t = self.transport_class(conn)
        try:
            t.load_server_moduli(self._moduli)
            t.add_server_key(self.host_key)
            server = _Server()
            t.start_server(server=server)
            chan = t.accept(20)
            if chan is None:
                return
            self.negotiated.append((t.kex_engine.name if t.kex_engine else "", t.host_key_type))
            server.shell.wait(10)
            self._shell(chan)
        except Exception:
            pass
        finally:
            t.close()

    def _shell(self, chan):
        prompt = f"\r\n{HOSTNAME}#"
        chan.sendall(prompt.encode())
        buf = b""
        while True:
            data = chan.recv(1024)
            if not data:
                return
            buf += data
            while b"\n" in buf or b"\r" in buf:
                cut = min(i for i in (buf.find(b"\r"), buf.find(b"\n")) if i >= 0)
                line, buf = buf[:cut].decode(errors="replace").strip(), buf[cut + 1:].lstrip(b"\r\n")
                if line in ("exit", "logout"):
                    chan.close()
                    return
                if line:
                    self.commands.append(line)
                out = RESPONSES.get(line, INVALID) if line else ""
                chan.sendall((line + "\r\n" + out.replace("\r\n", "\n").replace("\n", "\r\n") + prompt).encode())

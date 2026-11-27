# switchscan

Scans network switches and pulls their topology: LLDP/CDP neighbors, interfaces, VLANs,
MAC address tables and ARP. It can follow neighbors from switch to switch, and it works out
which access port each device (MAC/IP) is plugged into.

When a scan finishes, it asks for a name for the topology (press Enter to use the first switch's
name) and saves the run in its own dated folder:

```text
scan-output/
  HQ Campus/
    2026-11-24_14-30-05/
      topology.html  topology.json  topology.dot
      links.csv  neighbors.csv  ports.csv  mac_table.csv  arp.csv  (endpoints.csv with --hosts)
      core-sw1/
        device.json  ports.csv  interfaces.csv  neighbors.csv  mac_table.csv  arp.csv  vlans.csv
        cli/          (SSH scans only: the raw output of each show command)
      access-sw1/
      access-sw2/
```

Scanning the same topology again adds a new dated folder next to the old one, so earlier runs are
kept.

| File | What's in it |
|---|---|
| `topology.html` | Interactive diagram plus searchable tables (ports, neighbors, MACs, ARP, VLANs, links, and host computers with `--hosts`). Open it in any browser. It works offline. |
| `topology.json` | Everything collected, for scripts and other tools |
| `links.csv`, `neighbors.csv`, `ports.csv`, `mac_table.csv`, `arp.csv` | Tables for the whole topology that you can open in Excel |
| `endpoints.csv` | Which switch port each host computer is plugged into (only with `--hosts`) |
| `topology.dot` | Graphviz diagram (`dot -Tsvg topology.dot -o topology.svg`) |
| `<switch name>/` | One folder per switch found, holding only that switch's data |

## Setup

Requires Python 3.10+.

```powershell
cd switch-topology
python -m pip install --user pysnmp netmiko
```

Run everything below from the `switch-topology` folder (or install it with
`python -m pip install --user -e .` to get a `switchscan` command).

## Usage

Try it without a switch. This scans a built-in simulated 3-switch network:

```powershell
python -m switchscan --demo --open
```

Scan a real switch. With no credential options, it asks how to connect before scanning:

```powershell
python -m switchscan 10.0.99.1 --open
```

```text
How should switchscan log in to the switch?
  1) SNMP v2c (community string)  (default)
  2) SNMP v3 (user + passphrases)
  3) SSH (CLI login)
  4) SNMP v1
Choose 1-4 [1]: 3
Switch platform:
  1) Cisco IOS  (default)
  ...
SSH username: admin
SSH password:
Enable secret (press Enter if not needed):

Find the other switches through CDP/LLDP and scan them with the same SSH login? [Y/n]:
Add end devices (PCs, servers, printers, phones) to the topology? [y/N]:

Scanning 10.0.99.1 via SSH (cisco_ios) as admin, crawling to every switch found (up to 50)
```

Passwords, passphrases and community strings are hidden as you type. SNMPv3 passphrases must be
at least 8 characters, and it asks again if one is too short. It prompts only for what you didn't
supply, so `-v 3 -u netops` still asks for the two passphrases. In scripts, pass `--no-prompt`
(plus `-n NAME` and `--crawl` or `--no-crawl`) and supply secrets through the environment variables
listed below.

### Crawling the network

Answer **Y** to the crawl question (or pass `--crawl`) and switchscan finds the rest of the network
by itself:

1. It scans the switch you gave it and reads its CDP and LLDP neighbors.
2. Every neighbor that is a switch or router and advertises a management IP is logged in to with
   the same SSH user and password (or SNMP credentials).
3. Those switches' neighbors are scanned in turn, until no new switches turn up.

Over SSH, each neighbor's platform (IOS/IOS-XE, NX-OS or Arista EOS) is worked out from what it
advertises over CDP/LLDP, so a mixed Cisco/Arista network crawls correctly from one starting switch.
A neighbor that gives no platform details is assumed to run the same OS as the switch that reported
it. Vendors switchscan can't read over SSH (Aruba, Juniper, Meraki and so on) are listed as
skipped rather than logged in to. Switches that refuse the login or can't be reached are listed at
the end of the scan, and the crawl carries on without them.

Only network gear is logged in to: never access points, phones, servers or PCs (even an ESXi host that
advertises itself as a switch), and never anything without a management IP. The crawl stops after `--max-devices` switches (50 by default). `--depth N`
limits it to N hops from the starting switch.

### End devices (host computers and phones)

By default the topology only shows network equipment: switches, routers, firewalls and access points.
End devices (PCs, servers, printers, cameras, storage and IP phones) are left off. Answer **y** to the
end-device question (or pass `--hosts`) to add them:

- **End devices that announce themselves over LLDP/CDP**, such as ESXi hosts and phones.
- **Every device found in the switches' MAC tables on an access port**, labelled with its IP (from the
  ARP tables) or MAC address. These appear as small nodes on a dashed line to the exact switch port
  they're plugged into.

With them on, the report also gets a **Host computers** tab and `endpoints.csv`. Each switch's folder
always keeps its full MAC, ARP and neighbor tables either way. `--no-hosts` skips the question.

**How end devices are recognised.** The capability flags a device advertises aren't trusted on their
own: ESXi hosts call themselves a "Switch", Linux servers running lldpd usually say "Bridge, Router",
and many PCs and docks send no flags at all. So switchscan reads the platform and OS description first.
A network OS (Cisco IOS/NX-OS, Arista EOS, Aruba, Junos, FortiGate, pfSense, Cumulus and so on) means
network gear. A server/PC OS, printer, camera or NAS means an end device. The flags are only used when
the description doesn't say. A neighbor with no description and no flags is treated as an end device,
because switches always send a description. The crawl uses the same check, so switchscan only ever
logs in to network gear, never to a server that calls itself a switch.

Scan over SNMP v2c without prompts, crawling every switch found:

```powershell
python -m switchscan 10.0.99.1 -c public --crawl --no-prompt --open
```

Scan a switch and everything it connects to, up to 2 hops away:

```powershell
python -m switchscan 10.0.99.1 -c public --depth 2
```

SNMPv3 with authentication and encryption (the passphrases are prompted for):

```powershell
python -m switchscan 10.0.99.1 -v 3 -u netops --auth-proto sha256 --priv-proto aes
```

SSH instead of SNMP (Cisco IOS/IOS-XE/NX-OS, Arista EOS):

```powershell
python -m switchscan 10.0.99.1 --ssh cisco_ios --ssh-user admin --crawl
```

Other useful options:

- `-o DIR` sets the base output folder (default `scan-output`).
- `-n NAME` names the topology up front, so it isn't asked for after the scan.
- `--no-mac` skips the MAC table, which is faster on large switches.
- `--format html,csv` writes only some of the outputs.
- `--max-devices N` caps a crawl.
- `--timeout` and `--retries` tune SNMP for slow links.

Run `python -m switchscan --help` for the full list.

You can supply secrets through environment variables, so they don't end up in shell history:
`SWITCHSCAN_COMMUNITY`, `SWITCHSCAN_AUTH_KEY`, `SWITCHSCAN_PRIV_KEY`, `SWITCHSCAN_SSH_PASSWORD`,
`SWITCHSCAN_ENABLE_SECRET`.

## What it reads

**SNMP** (read-only; it never writes to the switch):

| Data | MIB |
|---|---|
| Name, model, uptime, location | SNMPv2-MIB `system` |
| Interfaces, speed, status, descriptions | IF-MIB `ifTable` / `ifXTable` |
| Neighbors (any vendor) | LLDP-MIB (IEEE 802.1AB) |
| Neighbors (Cisco) | CISCO-CDP-MIB |
| MAC table, VLANs, port VLAN | Q-BRIDGE-MIB, BRIDGE-MIB |
| Cisco MAC table and VLANs | BRIDGE-MIB per VLAN (`community@vlan` / v3 context `vlan-N`), CISCO-VTP-MIB, CISCO-VLAN-MEMBERSHIP-MIB |
| IP ↔ MAC | IP-MIB ARP tables |

**SSH**: `show version`, `show interfaces status`, `show lldp neighbors detail`,
`show cdp neighbors detail`, `show mac address-table`, `show ip arp` and `show vlan`. The output is
parsed with the ntc-templates TextFSM library.

### Older Cisco switches (2960, 3560, 3560-CX, 3750 and similar)

Choose **Cisco IOS** (`--ssh cisco_ios`). These switches work without any extra settings:

- **Old SSH crypto.** IOS 12.x and 15.x only offer SHA-1 key exchange
  (`diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1`)
  and the `ssh-rsa` host key. Current versions of the SSH library switchscan uses (paramiko) have
  removed these, so a plain connection fails with "Incompatible ssh peer". switchscan adds them back
  as a last resort: a switch that supports modern algorithms still gets modern ones, and the SHA-1
  ones are only used when a switch offers nothing newer. When that happens, the scan notes it as a
  warning for that switch, because the switch's SSH could use an upgrade.
- **Slow CPUs.** Logins and long MAC tables get extra time.
- **IOS 12.x commands.** If `show mac address-table` is rejected, `show mac-address-table` is used
  instead.
- **No LLDP.** Many older switches only run CDP. "LLDP is not enabled" is shown as a warning and
  CDP is used for neighbors.

Not supported: switches that only allow SSH version 1 or Telnet. Run `ip ssh version 2` on the
switch (it needs a crypto image and an RSA key: `crypto key generate rsa modulus 2048`).

## How the topology is built

- **Links.** Each switch reports its neighbors. The same link seen from both ends, or through both
  LLDP and CDP, is merged into one. Interface names are matched loosely, so `GigabitEthernet1/0/1`
  matches `Gi1/0/1`.
- **Crawling.** See [Crawling the network](#crawling-the-network). Only neighbors recognised as
  network gear are logged in to (see [End devices](#end-devices-host-computers-and-phones)). A switch reached through two
  different addresses is only scanned once, because switches are matched by name.
- **Host computers (`--hosts`).** A MAC address is learned on every switch along its path. The host's location is
  the port that doesn't lead to another switch. IPs come from every ARP table collected, so an
  L3 core's ARP table fills in IPs for hosts on the access switches. If a MAC is only ever seen on an
  uplink, it's marked "beyond scan" (the device sits past a switch that wasn't scanned).

## Switch-side requirements

- SNMP read access (v2c community, or a v3 user) from the machine running the scan. The
  switch's SNMP view must include the MIBs above. Some vendors' default views exclude LLDP or
  BRIDGE-MIB.
- LLDP and/or CDP must be enabled for neighbor discovery.
- On Cisco IOS, the MAC table is read once per VLAN. With SNMPv3 that requires
  `snmp-server group <grp> v3 priv context vlan- match prefix`.

## Tests

```powershell
python -m pip install --user snmpsim pysmi   # only needed for the SNMP end-to-end test
python -m unittest discover -s tests -v
```

- `test_topology`: crawling, link merging, endpoint location, and the named/dated output folders
  with one folder per switch.
- `test_ssh_parse`: parsing of captured Cisco IOS command output.
- `test_legacy_ssh`: SSH to a fake old Catalyst on localhost that only offers SHA-1 key exchange and
  `ssh-rsa`, plus IOS 12.x commands and no LLDP. It runs the full SSH collection against it.
- `test_ssh_crawl`: crawling a mixed Cisco IOS / NX-OS / Arista network over SSH with one login,
  including skipped vendors, failed logins and crawl limits.
- `test_cli`: the credential and topology-name prompts, using scripted answers.
- `test_snmpsim`: serves the demo network from the snmpsim SNMP agent on localhost and scans it
  with the real SNMP code (v1, v2c, v3 auth+priv, Cisco per-VLAN tables, wrong community).

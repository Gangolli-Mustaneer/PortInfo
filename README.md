# PORTINFO

**A command-line port reference tool for Kali Linux and any Linux system.**
Type a port number or a service name and get everything you need to remember about it, so you don't have to look it up again.

> *"I Break to Build, I Scan to Secure."* - SPYxKB

---

## What it does

For every port you look up, PORTINFO shows:

| Field | Example (SSH, port 22) |
|---|---|
| **Service** | SSH |
| **Protocol** | TCP |
| **Used for** | Encrypted remote shell, file copy and tunnelling |
| **How to access** | `ssh user@<ip>` |
| **Why it is risky** | Weak passwords, brute force, leaked keys, old versions |
| **Tools to check/test** | nmap, ssh-audit |
| **How to harden** | Key-only auth, fail2ban, `PermitRootLogin no` |

It works fully offline and never touches the network. It is a notebook, not a scanner.

## Features

- Detailed notes for **40 commonly exposed ports** (FTP, SSH, Telnet, SMTP, DNS, HTTP/HTTPS, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, VNC and more)
- Lookup by **port number** (`22`) or **name** (`ssh`, `smb`, `rdp`)
- **Every port from 0 to 65535 is answered.** Ports outside the database fall back to your system's service list and show how to identify what is really listening
- `search` across all notes (for example `search brute`)
- `save` writes your lookup to `~/port_notes.txt` for your own records
- **14 random ASCII banners.** One is shown at random on every run, including the SPYxKB banner, the project-name banner and 12 animal roast banners
- Colour output, with automatic fallback to plain ASCII on terminals without UTF-8
- Zero dependencies: Python standard library only

## Requirements

- Python 3.7 or newer
- Any Linux terminal (built and tested with Kali in mind). Also works on macOS and Windows terminals

## Installation

```bash
git clone https://github.com/<your-username>/portinfo.git
cd portinfo
chmod +x portinfo.py
```

No `pip install` is needed.

## Usage

**Interactive mode**

```bash
python3 portinfo.py
```

**One-shot lookup**

```bash
python3 portinfo.py 22
python3 portinfo.py ssh
python3 portinfo.py "port 3389"
```

### Interactive commands

| Command | What it does |
|---|---|
| `22`, `ssh`, `port 22` | Look up a port or service |
| `list` | Show every port in the detailed database |
| `search <word>` | Find entries that mention a word |
| `save` | Save the last lookup to `~/port_notes.txt` |
| `banner` | Show a random banner |
| `banner <n>` | Show banner number `n` (1 to 14) |
| `help` | Show the command list |
| `quit` | Exit |

### Example

```
portinfo> rdp

Service: RDP (port 3389)
Protocol: TCP
Used for: Windows Remote Desktop.
How to access: xfreerdp /v:<ip> /u:user   |   rdesktop <ip>
Why it is risky: Brute force, credential stuffing, BlueKeep on old Windows, ransomware entry point.
Tools to check/test: nmap --script rdp-enum-encryption -p3389 <ip>, hydra (authorised)
How to harden: Enable NLA, MFA, VPN/RD Gateway, patch, never expose directly.
```

### Colours

Colours show automatically in a terminal. To force them when piping output:

```bash
FORCE_COLOR=1 python3 portinfo.py ssh
```

## Ports in the detailed database

`21` FTP, `22` SSH, `23` Telnet, `25` SMTP, `53` DNS, `67` DHCP, `69` TFTP, `80` HTTP, `88` Kerberos, `110` POP3, `111` RPCbind, `123` NTP, `135` MSRPC, `139` NetBIOS, `143` IMAP, `161` SNMP, `389` LDAP, `443` HTTPS, `445` SMB, `465` SMTPS, `514` Syslog, `587` SMTP Submission, `636` LDAPS, `873` rsync, `993` IMAPS, `995` POP3S, `1433` MSSQL, `1521` Oracle, `2049` NFS, `2375` Docker API, `3306` MySQL, `3389` RDP, `5432` PostgreSQL, `5900` VNC, `5985` WinRM, `6379` Redis, `8080` HTTP-Alt, `9200` Elasticsearch, `11211` Memcached, `27017` MongoDB

## Customising

**Add a port.** Add one entry to the `DB` dictionary in `portinfo.py`:

```python
8443: ("HTTPS-Alt", "TCP", "What it is used for.",
       "how you connect, e.g. curl -k https://<ip>:8443",
       "why it is risky",
       "tools used to check it",
       "how to harden it"),
```

Optionally add a name shortcut to `ALIASES`, for example `"tomcat": 8080`.

**Add a banner.** Paste the ASCII art as a raw string and add one line to the `FUNNY` list. The speech bubble sizes itself.

## Project structure

```
portinfo/
├── portinfo.py    # the whole tool
├── README.md
└── .gitignore
```

## Legal and ethical use

This tool only displays reference information. The commands it lists (nmap, hydra, and so on) can be harmful if used without permission.

**Only test systems you own or have written authorisation to test.** Unauthorised scanning or access is illegal in most countries. The author is not responsible for misuse.

## Contributing

Pull requests that add ports, fix inaccurate notes or add banners are welcome. Please keep every note to the same seven fields so entries stay consistent.

## License

Add the license of your choice here (MIT is a common choice for small tools).

## Author

**SPYxKB** - *The Creator, The Player, The Hacker*

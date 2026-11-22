#!/usr/bin/env python3
"""
portinfo.py - Personal port reference tool for Kali / Linux.

Type a port number (22) or service name (ssh) and get: what it is used for,
how you connect to it, why it is risky, tools used to check it, and how to
harden it. Ports not in the built-in database fall back to the system's
IANA service list (socket.getservbyport), so 0-65535 are all answered.

Usage:
    python3 portinfo.py            # interactive mode
    python3 portinfo.py 22         # one-shot lookup
    python3 portinfo.py ssh
Only use these techniques on systems you own or are authorised to test.
"""
import os
import socket
import sys
from datetime import datetime

# port: (name, protocol, purpose, how_to_access, why_risky, tools, hardening)
DB = {
    21: ("FTP", "TCP", "File transfer. Sends login and data in cleartext.",
         "ftp <ip>   (try user 'anonymous' if allowed)",
         "Cleartext credentials, anonymous login enabled, weak passwords, old vulnerable daemons (vsftpd, ProFTPD).",
         "nmap -sV -sC -p21 <ip>, nmap --script ftp-anon, hydra (authorised password audits)",
         "Use SFTP/FTPS, disable anonymous login, restrict by IP, patch the daemon."),
    22: ("SSH", "TCP", "Encrypted remote shell, file copy (scp/sftp) and tunnelling.",
         "ssh user@<ip>   |   ssh -p 2222 user@<ip>   |   ssh -i key.pem user@<ip>",
         "Weak or default passwords, brute force, leaked private keys, old OpenSSH versions, root login enabled.",
         "nmap -sV -p22 --script ssh2-enum-algos <ip>, ssh-audit <ip>, hydra/medusa (authorised only)",
         "Key-only auth, PermitRootLogin no, fail2ban, non-default port optional, AllowUsers, keep OpenSSH updated."),
    23: ("Telnet", "TCP", "Legacy remote shell. No encryption.",
         "telnet <ip> 23",
         "Everything (including passwords) is readable on the network; often found on routers/IoT with default creds.",
         "nmap -sV -p23 <ip>, telnet, Wireshark to demonstrate cleartext",
         "Disable it, use SSH instead."),
    25: ("SMTP", "TCP", "Server-to-server email delivery.",
         "nc <ip> 25  then: EHLO test",
         "Open relay (spam), user enumeration via VRFY/EXPN, spoofing without SPF/DKIM/DMARC.",
         "nmap --script smtp-commands,smtp-open-relay -p25 <ip>, smtp-user-enum, swaks",
         "Disable VRFY/EXPN, no open relay, require auth and TLS, configure SPF/DKIM/DMARC."),
    53: ("DNS", "TCP/UDP", "Translates names to IPs.",
         "dig @<ip> example.com   |   nslookup example.com <ip>",
         "Zone transfer leaks internal hosts, cache poisoning, amplification DDoS if open resolver.",
         "dig axfr domain @<ip>, dnsrecon, dnsenum, fierce",
         "Restrict zone transfers, disable open recursion, use DNSSEC, rate limit."),
    67: ("DHCP", "UDP", "Hands out IP addresses (server 67, client 68).",
         "Automatic; inspect with: sudo nmap --script broadcast-dhcp-discover",
         "Rogue DHCP servers, starvation attacks on local network.",
         "nmap broadcast-dhcp-discover, Wireshark, yersinia (lab use)",
         "DHCP snooping on switches, port security."),
    69: ("TFTP", "UDP", "Very simple file transfer, no authentication.",
         "tftp <ip>  then: get filename",
         "Anyone can read/write files if filenames are known; often leaks router/switch configs.",
         "nmap -sU -p69 --script tftp-enum <ip>, tftp client",
         "Disable if unused, restrict to management VLAN and specific files."),
    80: ("HTTP", "TCP", "Unencrypted web traffic.",
         "curl -i http://<ip>   |   browser: http://<ip>",
         "Web app flaws (SQLi, XSS, file upload, outdated CMS), exposed admin panels, cleartext traffic.",
         "nmap -sV --script http-enum -p80 <ip>, nikto -h <ip>, gobuster dir, whatweb, Burp Suite",
         "Redirect to HTTPS, patch apps, WAF, remove default pages and debug info."),
    88: ("Kerberos", "TCP/UDP", "Authentication in Windows Active Directory.",
         "Used automatically by domain-joined machines; kinit user@REALM",
         "Roasting of weak service/user account passwords, ticket abuse, user enumeration.",
         "nmap -p88 --script krb5-enum-users, impacket tools (authorised AD tests)",
         "Strong long passwords for service accounts, AES only, monitor ticket requests."),
    110: ("POP3", "TCP", "Download email from server (cleartext).",
          "nc <ip> 110  then: USER x / PASS y",
          "Cleartext credentials, brute force.",
          "nmap -sV --script pop3-capabilities -p110 <ip>, hydra (authorised)",
          "Use POP3S (995) or IMAPS, enforce strong passwords."),
    111: ("RPCbind", "TCP/UDP", "Maps RPC services (used by NFS).",
          "rpcinfo -p <ip>",
          "Reveals which RPC services run; amplification abuse; gateway to NFS exposure.",
          "rpcinfo, nmap -sV -p111 --script rpcinfo <ip>",
          "Firewall it from untrusted networks, disable if NFS not needed."),
    123: ("NTP", "UDP", "Time synchronisation.",
          "ntpdate -q <ip>   |   ntpq -p <ip>",
          "Amplification DDoS (monlist on old servers), time tampering.",
          "nmap -sU -p123 --script ntp-info <ip>, ntpq",
          "Update ntpd/chrony, disable monlist, restrict queries."),
    135: ("MSRPC", "TCP", "Windows RPC endpoint mapper.",
          "rpcclient -U '' <ip>   |   rpcdump.py <ip>",
          "Enumerates Windows services/endpoints, historic wormable bugs.",
          "nmap -sV -p135 <ip>, impacket rpcdump, rpcclient",
          "Block at perimeter, patch Windows, host firewall."),
    139: ("NetBIOS-SSN", "TCP", "Legacy Windows file sharing session service.",
          "smbclient -L //<ip> -N   |   nbtscan <ip>",
          "Null sessions leaking users/shares, old SMB bugs, name spoofing (LLMNR/NBT-NS poisoning).",
          "nbtscan, enum4linux, nmap --script nbstat",
          "Disable NetBIOS over TCP/IP, block at firewall."),
    143: ("IMAP", "TCP", "Read/manage email on server.",
          "nc <ip> 143  then: a LOGIN user pass",
          "Cleartext login if no STARTTLS, brute force.",
          "nmap -sV --script imap-capabilities -p143 <ip>",
          "Force TLS/IMAPS (993), strong passwords, lockout policy."),
    161: ("SNMP", "UDP", "Network device monitoring/management.",
          "snmpwalk -v2c -c public <ip>",
          "Default community strings (public/private) leak full system info; v1/v2c are unencrypted; write access can change config.",
          "onesixtyone, snmpwalk, snmp-check, nmap -sU -p161 --script snmp-info",
          "Use SNMPv3, change communities, restrict by IP, read-only."),
    389: ("LDAP", "TCP/UDP", "Directory service (Active Directory).",
          "ldapsearch -x -H ldap://<ip> -b 'dc=example,dc=com'",
          "Anonymous bind leaks users/groups, cleartext binds.",
          "ldapsearch, nmap --script ldap-rootdse, ldapdomaindump",
          "Disable anonymous bind, require LDAPS/signing."),
    443: ("HTTPS", "TCP", "Encrypted web traffic (TLS).",
          "curl -k https://<ip>   |   openssl s_client -connect <ip>:443",
          "Same web-app flaws as HTTP plus weak TLS versions/ciphers, expired or self-signed certs, Heartbleed on old OpenSSL.",
          "sslscan <ip>, sslyze, testssl.sh, nmap --script ssl-enum-ciphers -p443 <ip>, nikto, Burp",
          "TLS 1.2+/1.3 only, strong ciphers, HSTS, valid certs, patch web apps."),
    445: ("SMB", "TCP", "Windows/Samba file and printer sharing.",
          "smbclient -L //<ip> -N   |   smbclient //<ip>/share -U user",
          "Historic wormable bugs (EternalBlue/MS17-010), null sessions, open shares, relay attacks, SMBv1.",
          "enum4linux, smbmap, crackmapexec/netexec, nmap --script smb-vuln*,smb-enum-shares",
          "Disable SMBv1, require SMB signing, patch, block 445 at the perimeter."),
    465: ("SMTPS", "TCP", "SMTP over implicit TLS.",
          "openssl s_client -connect <ip>:465",
          "Weak TLS config, credential brute force, relay misconfig.",
          "nmap --script smtp-commands -p465 <ip>, swaks",
          "Require auth, modern TLS, rate limit."),
    514: ("Syslog/rsh", "UDP/TCP", "Syslog (UDP) or legacy remote shell (TCP).",
          "logger -n <ip> -P 514 'test'",
          "Log injection/spoofing; rsh has no real authentication.",
          "nmap -sU -p514 <ip>",
          "Use TLS syslog (6514), disable rsh."),
    587: ("SMTP Submission", "TCP", "Authenticated mail sending from clients (STARTTLS).",
          "openssl s_client -starttls smtp -connect <ip>:587",
          "Credential stuffing, plaintext fallback.",
          "nmap -sV -p587 <ip>, swaks",
          "Enforce STARTTLS, MFA/app passwords, rate limit."),
    636: ("LDAPS", "TCP", "LDAP over TLS.",
          "ldapsearch -x -H ldaps://<ip>",
          "Weak certs/TLS, still exposes directory data to authenticated users.",
          "ldapsearch, openssl s_client",
          "Valid certs, restrict access, least-privilege accounts."),
    873: ("rsync", "TCP", "File synchronisation/backup.",
          "rsync --list-only rsync://<ip>/   |   rsync -av rsync://<ip>/module ./",
          "Unauthenticated modules expose backups and sensitive files.",
          "nmap -p873 --script rsync-list-modules <ip>",
          "Require auth, restrict by IP, read-only modules."),
    993: ("IMAPS", "TCP", "IMAP over TLS.",
          "openssl s_client -connect <ip>:993",
          "Brute force, weak TLS.",
          "nmap --script ssl-enum-ciphers -p993 <ip>",
          "Strong passwords, MFA, fail2ban."),
    995: ("POP3S", "TCP", "POP3 over TLS.",
          "openssl s_client -connect <ip>:995",
          "Brute force, weak TLS.",
          "nmap --script ssl-enum-ciphers -p995 <ip>",
          "Strong passwords, lockout policy."),
    1433: ("MSSQL", "TCP", "Microsoft SQL Server.",
           "sqlcmd -S <ip> -U user -P pass   |   impacket-mssqlclient user@<ip>",
           "Weak 'sa' password, xp_cmdshell abuse, exposed to internet, unpatched servers.",
           "nmap -p1433 --script ms-sql-info, impacket-mssqlclient",
           "Never expose publicly, disable sa, least privilege, disable xp_cmdshell."),
    1521: ("Oracle TNS", "TCP", "Oracle database listener.",
           "sqlplus user/pass@<ip>:1521/SID",
           "Default accounts, SID guessing, old listener bugs.",
           "nmap -p1521 --script oracle-sid-brute, odat (authorised)",
           "Listener password/ACLs, remove default accounts, patch."),
    2049: ("NFS", "TCP/UDP", "Unix network file system.",
           "showmount -e <ip>   |   sudo mount -t nfs <ip>:/share /mnt/x",
           "Exports open to everyone, no_root_squash allows root-level file access.",
           "showmount, nmap --script nfs-ls,nfs-showmount -p2049 <ip>",
           "Restrict exports by IP, root_squash, use NFSv4 with Kerberos."),
    2375: ("Docker API", "TCP", "Unencrypted Docker remote API.",
           "curl http://<ip>:2375/version   |   docker -H tcp://<ip>:2375 ps",
           "Unauthenticated access equals full control of the host.",
           "nmap -p2375 <ip>, curl",
           "Never expose; use the Unix socket or TLS with client certs (2376)."),
    3306: ("MySQL/MariaDB", "TCP", "MySQL database.",
           "mysql -h <ip> -u user -p",
           "Weak/empty root password, exposed to internet, old versions.",
           "nmap -sV --script mysql-info,mysql-empty-password -p3306 <ip>, hydra (authorised)",
           "Bind to localhost, strong passwords, firewall, least privilege."),
    3389: ("RDP", "TCP", "Windows Remote Desktop.",
           "xfreerdp /v:<ip> /u:user   |   rdesktop <ip>",
           "Brute force, credential stuffing, BlueKeep (CVE-2019-0708) on old Windows, ransomware entry point.",
           "nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p3389 <ip>, hydra (authorised)",
           "Enable NLA, MFA, VPN/RD Gateway, patch, never expose directly."),
    5432: ("PostgreSQL", "TCP", "PostgreSQL database.",
           "psql -h <ip> -U user -d dbname",
           "Weak passwords, permissive pg_hba.conf, exposed to internet.",
           "nmap -sV -p5432 <ip>, psql, hydra (authorised)",
           "Bind to localhost/VPN, scram-sha-256, strict pg_hba.conf."),
    5900: ("VNC", "TCP", "Remote desktop (weak or no encryption).",
           "vncviewer <ip>:5900",
           "No password or weak 8-char password, unencrypted screen sharing.",
           "nmap --script vnc-info,vnc-title -p5900 <ip>",
           "Tunnel over SSH/VPN, strong passwords, firewall."),
    5985: ("WinRM", "TCP", "Windows Remote Management (PowerShell remoting).",
           "evil-winrm -i <ip> -u user -p pass   (authorised testing)",
           "Valid credentials give a remote shell; weak admin passwords.",
           "nmap -p5985 <ip>, netexec winrm",
           "Restrict to admin hosts, use HTTPS (5986), strong creds."),
    6379: ("Redis", "TCP", "In-memory key/value database.",
           "redis-cli -h <ip>   then: INFO",
           "Often no authentication; can be abused to write files if exposed.",
           "nmap -p6379 --script redis-info <ip>, redis-cli",
           "Bind to localhost, requirepass/ACLs, protected-mode yes."),
    8080: ("HTTP-Alt", "TCP", "Alternate web port: proxies, Tomcat, Jenkins, dev servers.",
           "curl -i http://<ip>:8080",
           "Exposed admin consoles (Tomcat Manager, Jenkins), default credentials, dev/debug mode.",
           "nmap -sV --script http-title -p8080 <ip>, nikto, gobuster",
           "Remove default apps, authentication, restrict to internal network."),
    9200: ("Elasticsearch", "TCP", "Search/analytics engine REST API.",
           "curl http://<ip>:9200/   |   curl http://<ip>:9200/_cat/indices",
           "Often no auth: entire datasets can be read or deleted.",
           "nmap -p9200 --script http-title <ip>, curl",
           "Enable security/auth, bind to private network, firewall."),
    11211: ("Memcached", "TCP/UDP", "In-memory cache.",
            "nc <ip> 11211  then: stats",
            "No auth by default; UDP used for massive DDoS amplification; data leakage.",
            "nmap -sU -p11211 --script memcached-info <ip>",
            "Bind to localhost, disable UDP, firewall."),
    27017: ("MongoDB", "TCP", "NoSQL database.",
            "mongosh mongodb://<ip>:27017",
            "Older installs had no auth by default; many leaked databases.",
            "nmap -p27017 --script mongodb-info <ip>, mongosh",
            "Enable auth, bind to private IP, firewall, TLS."),
}

ALIASES = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53, "dhcp": 67,
    "tftp": 69, "http": 80, "kerberos": 88, "pop3": 110, "rpc": 111,
    "rpcbind": 111, "ntp": 123, "msrpc": 135, "netbios": 139, "imap": 143,
    "snmp": 161, "ldap": 389, "https": 443, "ssl": 443, "tls": 443,
    "smb": 445, "samba": 445, "smtps": 465, "syslog": 514, "submission": 587,
    "ldaps": 636, "rsync": 873, "imaps": 993, "pop3s": 995, "mssql": 1433,
    "sqlserver": 1433, "oracle": 1521, "nfs": 2049, "docker": 2375,
    "mysql": 3306, "mariadb": 3306, "rdp": 3389, "postgres": 5432,
    "postgresql": 5432, "vnc": 5900, "winrm": 5985, "redis": 6379,
    "elasticsearch": 9200, "elastic": 9200, "memcached": 11211,
    "mongodb": 27017, "mongo": 27017,
}

LABELS = ("Service", "Protocol", "Used for", "How to access", "Why it is risky",
          "Tools to check/test", "How to harden")

BOLD, CYAN, YEL, RST = "\033[1m", "\033[96m", "\033[93m", "\033[0m"
if not (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")):
    BOLD = CYAN = YEL = RST = ""


def resolve(query):
    """Return a port int from '22', 'ssh', 'port 22', 'ssh 22', or None."""
    for tok in query.lower().replace(",", " ").split():
        if tok.isdigit() and 0 <= int(tok) <= 65535:
            return int(tok)
        if tok in ALIASES:
            return ALIASES[tok]
    return None


def format_entry(port):
    if port in DB:
        vals = (f"{DB[port][0]} (port {port})",) + DB[port][1:]
        lines = []
        for label, val in zip(LABELS, vals):
            lines.append(f"{BOLD}{CYAN}{label}:{RST} {val}")
        return "\n".join(lines)
    # Fallback for the rest of 0-65535
    out = [f"{BOLD}{CYAN}Port:{RST} {port}"]
    for proto in ("tcp", "udp"):
        try:
            out.append(f"{BOLD}{CYAN}IANA {proto.upper()} service:{RST} {socket.getservbyport(port, proto)}")
        except OSError:
            pass
    if len(out) == 1:
        out.append("No registered service name on this system.")
    kind = ("well-known" if port < 1024 else
            "registered" if port < 49152 else "dynamic/private")
    out.append(f"{BOLD}{CYAN}Range:{RST} {kind} port")
    out.append(f"{YEL}Not in the detailed database. Identify what is really listening with:{RST}\n"
               f"  nmap -sV -p{port} <ip>   |   nc -v <ip> {port}   |   sudo ss -tulpn | grep :{port}")
    return "\n".join(out)


def strip_ansi(s):
    for c in (BOLD, CYAN, YEL, RST):
        s = s.replace(c, "")
    return s


def save_note(port, path=os.path.expanduser("~/port_notes.txt")):
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M} ===\n{strip_ansi(format_entry(port))}\n")
    print(f"Saved to {path}")


def list_ports():
    print(f"{'PORT':<7}{'SERVICE':<18}PROTO")
    for p in sorted(DB):
        print(f"{p:<7}{DB[p][0]:<18}{DB[p][1]}")


def search(term):
    term = term.lower()
    hits = [p for p, v in DB.items() if term in " ".join(map(str, v)).lower()]
    if not hits:
        print("No matches.")
    for p in sorted(hits):
        print(f"  {p:<6}{DB[p][0]}")


HELP = """Commands:
  <port or name>   e.g. 22, ssh, "port 3389", rdp
  list             show all ports in the detailed database
  search <word>    find entries mentioning a word (e.g. search brute)
  save             save the last lookup to ~/port_notes.txt
  banner [n]       show a random banner, or banner number n
  help / quit"""


# ---------------------------------------------------------------- banners
# 14 banners in total. Exactly ONE is picked at random every run.
import random
import re
import shutil
import textwrap

GRN, MAG, RED = "\033[92m", "\033[95m", "\033[91m"
BLU, WHT, ORG = "\033[94m", "\033[97m", "\033[38;5;208m"
if not (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")):
    GRN = MAG = RED = BLU = WHT = ORG = ""

COLOURS = {"RED": RED, "GRN": GRN, "MAG": MAG, "YEL": YEL, "CYAN": CYAN,
           "BLU": BLU, "ORG": ORG}

# Plain ASCII fallback if the terminal can't show box/block characters.
UTF = "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()
BOX = ("\u2554", "\u2550", "\u2557", "\u2551", "\u255a", "\u255d") if UTF \
    else ("+", "-", "+", "|", "+", "+")

INNER = 50          # fixed inside width of every frame
ANSI = re.compile(r"\x1b\[[0-9;]*m")
PROJECT = "PORTINFO"


# --------------------------------------------------------------- frame tools
def _row(vis_len, rendered, align="left"):
    pad = INNER - vis_len
    if pad < 0:
        raise ValueError("banner line wider than frame")
    left = pad // 2 if align == "center" else 1
    return (left, pad - left, rendered)


def frame(rows, border_colour):
    tl, h, tr, v, bl, br = BOX
    b = border_colour
    out = [f"{b}{tl}{h * INNER}{tr}{RST}"]
    for left, right, text in rows:
        out.append(f"{b}{v}{RST}{' ' * left}{text}{' ' * right}{b}{v}{RST}")
    out.append(f"{b}{bl}{h * INNER}{br}{RST}")
    return "\n".join(out)


def blank():
    return _row(0, "", "left")


def centered(text, colour=""):
    return _row(len(text), f"{colour}{text}{RST}", "center")


def centre_text(text, width, colour=""):
    pad = max(width - len(text), 0)
    left = pad // 2
    return " " * left + f"{colour}{text}{RST}"


def art_lines(art):
    return [l.rstrip() for l in art.strip("\n").split("\n")]


# ------------------------------------------------- banner 1: SPYxKB (block)
SPYXKB_ART = r'''
███████╗██████╗ ██╗   ██╗██╗  ██╗██╗  ██╗██████╗
██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝██║ ██╔╝██╔══██╗
███████╗██████╔╝ ╚████╔╝  ╚███╔╝ █████╔╝ ██████╔╝
╚════██║██╔═══╝   ╚██╔╝   ██╔██╗ ██╔═██╗ ██╔══██╗
███████║██║        ██║   ██╔╝ ██╗██║  ██╗██████╔╝
╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
'''


def banner_spyxkb():
    art = art_lines(SPYXKB_ART)
    aw = max(len(l) for l in art)
    total = INNER + 2
    left = " " * ((total - aw) // 2)
    out = [f"{BOLD}{WHT}{left}{l.ljust(aw)}{RST}" for l in art]
    out.append("")
    out.append(frame([
        centered("O W N E R     -    S P Y x K B", BOLD + GRN),
        centered('"I Break to Build, I Scan to Secure."', BOLD + GRN),
    ], GRN).replace("\n", "\n"))
    out.append("")
    out.append(centre_text("[ STEALTH ON  |  TRACE OFF  |  SCAN ON ]", total, BOLD + YEL))
    return "\n".join(out)


# --------------------------------- banner 2: project name (figlet "epic" style)
def _glyph(s):
    return [l.ljust(9) for l in s.strip("\n").split("\n")]


EPIC = {
    "P": _glyph(r'''
 _______ 
(  ____ )
| (    )|
| (____)|
|  _____)
| (      
| )      
|/       
'''),
    "O": _glyph(r'''
 _______ 
(  ___  )
| (   ) |
| |   | |
| |   | |
| |   | |
| (___) |
(_______)
'''),
    "R": _glyph(r'''
 _______ 
(  ____ )
| (    )|
| (____)|
|     __)
| (\ (   
| ) \ \__
|/   \__/
'''),
    "T": _glyph(r'''
_________
\__   __/
   ) (   
   | |   
   | |   
   | |   
   | |   
   )_(   
'''),
    "I": _glyph(r'''
_________
\__   __/
   ) (   
   | |   
   | |   
   | |   
___) (___
\_______/
'''),
    "N": _glyph(r'''
 _       
( (    /|
|  \  ( |
|   \ | |
| (\ \) |
| | \   |
| )  \  |
|/    )_)
'''),
    "F": _glyph(r'''
 _______ 
(  ____ \
| (    \/
| (__    
|  __)   
| (      
| )      
|/       
'''),
}


def banner_project():
    rows = ["".join(EPIC[ch][r] for ch in PROJECT).rstrip() for r in range(8)]
    w = max(len(r) for r in rows)
    rule = ("\u2550" if UTF else "=") * 40
    warn = ('\u26a0  DON\'T PANIC! I\'M JUST "LEARNING PORTS"... LEGALLY  \u26a0' if UTF
            else '/!\\  DON\'T PANIC! I\'M JUST "LEARNING PORTS"... LEGALLY  /!\\')
    out = [f"{BOLD}{RED}{r.ljust(w)}{RST}" for r in rows]
    out.append("")
    out.append(centre_text(rule, w, BOLD + RED))
    out.append(centre_text("THE TOOL THAT REMEMBERS YOUR PORTS...", w, BOLD + RED))
    out.append(centre_text(rule, w, BOLD + RED))
    out.append("")
    out.append(centre_text(warn, w, BOLD + WHT))
    return "\n".join(out)


# ------------------------------------------------------------ roast banners
COW = r'''
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
'''

CAT = r'''
        \     /\_____/\
         \   /  o   o  \
            ( ==  ^  == )
             )         (
            (   )   (   )
           ( (  )   (  ) )
          (__(__)___(__)__)
'''

SKULL = r'''
      \      .-"""""""-.
       \    /  _     _  \
           |  (_)   (_)  |
            \     ^     /
             \  |||||  /
              | |-|-| |
              '-------'
'''

OWL = r'''
        \    ,___,
         \   {o,o}
             /)_)
              " "
          ___|   |___
         /___________\
'''

ROBOT = r'''
         \     _____
          \   [ o_o ]
              /|___|\
             /_|[=]|_\
               |   |
              _|   |_
             (_/   \_)
'''

PENGUIN = r'''
        \     .--.
         \   |o_o |
             |:_/ |
            //   \ \
           (|     | )
          /'\_   _/`\
          \___)=(___/
'''

SNAKE = r'''
        \     _____
         \   / o o \
             \  v  /___
              \____    \___
                   \_____  \
              ______     \  |
             /  ___ \____/ /
             \_/   \______/
'''

GHOST = r'''
        \     .-"""""-.
         \   /         \
            |  ()   ()  |
            |     O     |
            |           |
            |  /\/\/\/\ |
            '-'-'-'-'-'-'
'''

SHARK = r'''
        \          |\
         \         | \
                   |  \
                   |   \
       ~~~~~~~~~~~~|____\~~~~~~~~~~~
         ~~~~  ~~~~~  ~~~~~~  ~~~~
'''

ALIEN = r'''
        \     .-------.
         \   /  _   _  \
            |  (O) (O)  |
             \    ~    /
              '-.___.-'
                 | |
              .--' '--.
              '-.   .-'
'''

LAPTOP = r'''
        \      .-------------.
         \     | root@kali   |
               | # whoami_   |
               | # nmap -sV  |
               '-------------'
              /______________\
             (________________)
'''

FISH = r'''
        \       ,
         \   .-'\-.__
            /  o      `>
            \_.-'/-'
                '
'''

FUNNY = [
    (COW, "YEL", "Moo! Forgot SMB is 445 again? Even I remember that, and I'm a cow."),
    (CAT, "MAG", "I sit on your keyboard all day and I still know port 443 better than you."),
    (SKULL, "RED", "Telnet on port 23? Your passwords are already dead, buddy."),
    (OWL, "CYAN", "Who? Who forgot port 22 again? Whooo? You did. Again."),
    (ROBOT, "GRN", "Beep boop. 65535 ports scanned, and you still can't remember 5 of them."),
    (PENGUIN, "CYAN", "I use Kali, btw. And I still read my notes before the scan. Try it."),
    (SNAKE, "GRN", "Written in Python, shipped with love. Still can't remember port 5432?"),
    (GHOST, "MAG", "Boo! That open port 23 is haunting your entire network."),
    (SHARK, "CYAN", "Nmap is circling your open ports like me. Patch them or get eaten."),
    (ALIEN, "GRN", "Take me to your leader. Also, what even is port 8080?"),
    (LAPTOP, "YEL", "root@kali:~# whoami. Answer: someone who forgot port 3389. Again."),
    (FISH, "RED", "Clicked that link? Congrats, you're today's catch. Phishing 101."),
]


def bubble(text, width=40):
    lines = textwrap.wrap(text, width)
    w = max(len(l) for l in lines)
    out = [" " + "_" * (w + 2)]
    if len(lines) == 1:
        out.append(f"< {lines[0].ljust(w)} >")
    else:
        for i, l in enumerate(lines):
            l = l.ljust(w)
            if i == 0:
                out.append(f"/ {l} \\")
            elif i == len(lines) - 1:
                out.append(f"\\ {l} /")
            else:
                out.append(f"| {l} |")
    out.append(" " + "-" * (w + 2))
    return out


def roast_banner(i, fixed_colour=False):
    art, colour, line = FUNNY[i]
    body = bubble(line) + [""] + art_lines(art)
    c = COLOURS[colour] if fixed_colour else random.choice(list(COLOURS.values()))
    rows = [blank()]
    for l in body:
        rows.append(_row(len(l), f"{c}{l}{RST}", "left"))
    rows.append(blank())
    return frame(rows, c)


# ------------------------------------------------------------- the picker
# index 0 = SPYxKB, 1 = project name, 2.. = animals
BANNER_COUNT = 2 + len(FUNNY)


def render_banner(n, fixed_colour=False):
    if n == 0:
        return banner_spyxkb()
    if n == 1:
        return banner_project()
    return roast_banner(n - 2, fixed_colour)


def show_banner(n=None):
    """Print exactly ONE banner: random unless n is given (0-based)."""
    if n is None:
        # block-character banners need UTF-8; animals are plain ASCII
        n = random.choice(range(BANNER_COUNT) if UTF else range(2, BANNER_COUNT))
    text = render_banner(n)
    width = max(len(ANSI.sub("", l)) for l in text.split("\n"))
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    print()
    if cols < width:            # narrow terminal: compact, never wraps/breaks
        print(f"{BOLD}{CYAN}{PROJECT}{RST} - by SPYxKB")
    else:
        print(text)
        print()
        print(f"{BOLD}{'(authorised / educational use only)'.center(width)}{RST}")
    print()


def main():
    show_banner()
    if len(sys.argv) > 1:
        port = resolve(" ".join(sys.argv[1:]))
        print(format_entry(port) if port is not None else "Unknown port or service.")
        return
    print("Type a port or service name. 'help' for commands.")
    last = None
    while True:
        try:
            q = input(f"\n{BOLD}portinfo>{RST} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q:
            continue
        cmd = q.lower()
        if cmd in ("quit", "exit", "q"):
            break
        if cmd == "help":
            print(HELP)
        elif cmd == "list":
            list_ports()
        elif cmd.startswith("search "):
            search(q[7:])
        elif cmd.split()[0] == "banner":
            arg = cmd.split()[1:]
            n = int(arg[0]) - 1 if arg and arg[0].isdigit() else None
            if n is not None and not 0 <= n < BANNER_COUNT:
                print(f"Pick a number from 1 to {BANNER_COUNT}.")
            else:
                show_banner(n)
        elif cmd == "save":
            save_note(last) if last is not None else print("Look something up first.")
        else:
            port = resolve(q)
            if port is None:
                print("Not recognised. Try a port number (0-65535) or a name like ssh, smb, rdp.")
            else:
                last = port
                print()
                print(format_entry(port))


if __name__ == "__main__":
    main()
# Network Service Enumerator and Scanner

A Bash script that automates scanning, service enumeration, and basic exploitation of discovered services across live hosts in a network.

---

## Features

- ✅ IP address and CIDR block input validation
- ✅ Automatic discovery of live hosts
- ✅ TCP and UDP port scanning using `nmap`
- ✅ Service-specific enumeration using:
  - `enum4linux-ng` for SMB (port 445)
  - `smbmap` for SMB share enumeration
  - `snmpwalk` for SNMP enumeration
  - `smtp-user-enum` for SMTP servers (port 25)
  - `GetUserSPNs.py` (Impacket) for Kerberoasting attacks
- ✅ Automatic report generation with detailed outputs
- ✅ Error logging for missing tools
- ✅ Cleans outputs by removing ANSI escape codes

---

## Requirements

- Bash (Linux/Unix environment)
- `nmap`
- `enum4linux-ng`
- `smbmap`
- `snmpwalk`
- `smtp-user-enum`
- `impacket` package (`GetUserSPNs.py` script)

- Optional: `sed`, `grep`, `cut` (should already be available on most systems)

Install missing tools with:

```bash
sudo apt install nmap snmp snmp-mibs-downloader
pip install impacket
```
Service | Port | Protocol | Additional Plugins / Tools
FTP | 21 | TCP | ftp-anon
SSH | 22 | TCP | ssh2-enum-algos
Telnet | 23 | TCP | telnet-ntlm-info
SMB | 445 | TCP | smb-enum-shares, smb-enum-users, enum4linux-ng, smbmap
SNMP | 161 | UDP | snmp-sysdescr, snmpwalk
LDAP | 389 | TCP | ldap-rootdse, Kerberoasting
Kerberos | 88 | TCP | Kerberoasting
NFS | 2049 | UDP | nfs-ls, nfs-showmount, nfs-statfs
SQL Databases | Various | TCP | ms-sql-info, mysql-enum, pgsql-brute
HTTP/HTTPS | 80/443/5985 | TCP | http-headers, ssl-enum-ciphers
And many more... |  |  | 

Notes ⚠️

    ⚡ Speed: The script uses --min-rate=1000 for faster scans. Tune this if you get network instability.

    🛡️ Ethics: Only run this script on networks you own or have explicit permission to scan!

    📂 Custom Services: You can extend or modify the SERVICES array at the top of the script.

Troubleshooting 🛠️

    If tools like enum4linux-ng or GetUserSPNs.py are not found, ensure they are in your PATH or installed properly.

    Missing modules? Install Python dependencies using pip install -r requirements.txt (for Impacket or Enum4linux-ng).

    Nmap script failures? Some nmap scripts require root privileges (sudo).

License 📄

    This script is provided as-is for educational and authorized penetration testing purposes only.



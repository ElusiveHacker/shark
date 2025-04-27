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

Notes ⚠️

    ⚡ Speed: The script uses --min-rate=1000 for faster scans. Tune this if you get network instability.

    🛡️ Ethics: Only run this script on networks you own or have explicit permission to scan!

    📂 Custom Services: You can extend or modify the SERVICES array at the top of the script.

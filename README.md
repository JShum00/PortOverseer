# Port Overseer
### Vulnerability Hunt & Scan

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Built With](https://img.shields.io/badge/Built%20With-OpenAI%20Codex-412991?logo=openai&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

```
                       _______    ______     _______  ___________
                      |   __ "\  /    " \   /"      \("     _   ")
                      (. |__) :)// ____  \ |:        |)__/  \\__/
                      |:  ____//  /    ) :)|_____/   )   \\_ /
                      (|  /   (: (____/ //  //      /    |.  |
                     /|__/ \   \        /  |:  __   \    \:  |
                    (_______)   \"_____/   |__|  \___)    \__|

    ______  ___      ___  _______   _______    ________  _______   _______   _______
   /    " \|"  \    /"  |/"     "| /"      \  /"       )/"     "| /"     "| /"      \
  // ____  \\   \  //  /(: ______)|:        |(:   \___/(: ______)(: ______)|:        |
 /  /    ) :)\\  \/. ./  \/    |  |_____/   ) \___  \   \/    |   \/    |  |_____/   )
(: (____/ //  \.    //   // ___)_  //      /   __/  \\  // ___)_  // ___)_  //      /
 \        /    \\   /   (:      "||:  __   \  /" \   :)(:      "|(:      "||:  __   \
  \"_____/      \__/     \_______)|__|  \___)(_______/  \_______) \_______)|__|  \___)
```

> *"Scan your machine, find known vulnerabilities, get actionable fixes — no internet required."*

---

## What is Port Overseer?

Port Overseer is a locally-executed, offline-capable command-line security tool that scans your machine's open ports, identifies running services, and cross-references them against a locally-cached CVE (Common Vulnerabilities and Exposures) database sourced from NIST's National Vulnerability Database.

It generates severity-rated vulnerability reports in both `.txt` and `.json` formats, complete with remediation recommendations — all without sending your data anywhere.

**Designed for environments where internet access is restricted or untrusted.** After an initial CVE database sync, Port Overseer runs entirely air-gapped.

---

## Features

- **Three scan modes** — Quick (top 1,000 ports), Full (all 65,535 ports), and Custom Range
- **Service & version detection** — powered by Nmap's `-sV` flag
- **CVE correlation** — cross-references detected services against a local SQLite CVE database
- **Severity ratings** — Critical / High / Medium / Low based on CVSS scores
- **Color-coded terminal output** — real-time findings with severity-based highlighting
- **Dual report formats** — human-readable `.txt` and machine-readable `.json`
- **Offline-first** — runs fully air-gapped after initial database sync
- **Backup rotation** — retains last 3 CVE database snapshots automatically
- **Cross-platform** — supports Linux and Windows

---

## Requirements

- Python 3.10 or higher
- [Nmap](https://nmap.org/) installed on your system
- Administrator / root privileges (required for Nmap raw socket access)

### Python dependencies

```
python-nmap
requests
colorama
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/JShum00/PortOverseer.git
cd PortOverseer
```

### 2. Create and activate a virtual environment

**Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Nmap

**Linux (Debian/Ubuntu/Mint):**
```bash
sudo apt install nmap
```

**Windows:**
Download the installer from [nmap.org](https://nmap.org/download.html) and follow the setup wizard.

---

## Usage

Port Overseer must be run with elevated privileges.

**Linux:**
```bash
sudo /path/to/venv/bin/python3 main.py
```

**Windows:**
Open an Administrator command prompt, then:
```cmd
python main.py
```

### Main Menu

```
1. Quick Scan       — Scans top 1,000 common ports
2. Full Scan        — Scans all 65,535 ports (slower)
3. Custom Range     — Scans a user-defined port range
4. Update Database  — Downloads latest CVE data from NVD
5. Help             — Shows help and usage info
6. Exit
```

### First-time setup

On first run, select **option 4** to download the CVE database before scanning. This requires an internet connection and takes approximately 20–30 minutes to download all ~341,000 CVEs. Subsequent scans run fully offline. If you don't want to run the update function on the machine you intend to scan, you can update the application on another Trusted machine and then transfer to the untrusted machine via USB/Flash drive.

---

## Example Output

### Terminal (color-coded)

```
Port 631 | Service: cups | Version: CUPS 2.4 | 3 CVEs found - highest: High
  CVE-2023-32360 | Severity: High
  CVE-2022-26691 | Severity: Medium
  CVE-2023-34241 | Severity: Medium

Port 22 | Service: ssh | Version: OpenSSH 8.9 | No known CVEs
```

### Report files

Reports are saved to the `/reports` directory with a timestamp:

```
reports/
├── scan_20260330_200352.txt
└── scan_20260330_200352.json
```

**Sample `.txt` report:**
```
PORT OVERSEER
Scan Type: Quick Scan
Timestamp: 20260330_200352
Total Ports Scanned: 3

Summary
Total Open Ports: 3
Total CVEs Found: 3
Highest Severity: High

Findings
Port: 631 | Protocol: tcp | Service: cups | Version: CUPS 2.4
  CVE ID: CVE-2023-32360
    Severity: High
    CVSS Score: 7.5
    Description: ...
    Remediation: Refer to vendor advisory and apply available patches or mitigations.
    Reference URL: https://nvd.nist.gov/vuln/detail/CVE-2023-32360
```

---

## Project Structure

```
port-overseer/
├── main.py          # Entry point — menu, ASCII art, routing
├── scanner.py       # Nmap integration — port/service scanning
├── cve_lookup.py    # SQLite CVE database and lookup logic
├── updater.py       # NVD data downloader with progress bar
├── reporter.py      # .txt and .json report generation
├── colors.py        # ANSI color output helpers
├── data/
│   ├── cve_db.sqlite          # Active CVE database
│   └── cve_db_backup_*.sqlite # Automatic backups (up to 3)
├── reports/         # Generated scan reports
├── requirements.txt
└── README.md
```

---

## Known Limitations

- **Localhost only** — Port Overseer scans `127.0.0.1` exclusively by design. This is an intentional ethical constraint to prevent misuse as a network attack tool.
- **CVE database staleness** — The local database reflects NVD data at the time of the last update. Run option 4 periodically to stay current.
- **Service matching accuracy** — CVE correlation depends on Nmap's service and version detection. Unrecognized or generic service strings may return no CVE matches.
- **Full download on update** — The current update mechanism re-downloads the full NVD dataset. Incremental updates are planned for a future version.

---

## Planned Features

- Incremental CVE database updates (fetch only new/modified entries since last sync)
- Full Local Audit mode — scans both localhost and the host's LAN IP for a complete picture
- Progress indicator during CVE insertion

---

## Legal Disclaimer

> Port Overseer is intended strictly for use on systems you own or have explicit written authorization to audit. Unauthorized port scanning may violate local, state, federal, or international law. The tool scans `localhost (127.0.0.1)` only by design. The author assumes no liability for misuse of this software.

---

## Author

**Johnny Shumway**
Cybersecurity student | Aspiring SOC Analyst
Built for the Handshake × OpenAI Codex Creator Challenge — March 2026

---

## Acknowledgements

- [NIST National Vulnerability Database](https://nvd.nist.gov/) — CVE data source
- [Nmap](https://nmap.org/) — port scanning engine
- [OpenAI Codex](https://openai.com/) — used to build this project
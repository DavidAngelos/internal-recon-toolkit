# Internal Recon Toolkit

A terminal-based Python toolkit for internal network reconnaissance during black-box security assessments.

## 🔧 Requirements

- Python 3.8+
- [`rich`](https://pypi.org/project/rich/) (for TUI)
- `masscan`, `nmap`, `netdiscover`, `nbtscan` (installed via `apt` on Kali/Debian)

## 📦 Installation

```bash
sudo apt install masscan nmap netdiscover nbtscan
pip install rich
```

## 🚀 Usage

```bash
python3 internal_recon_toolkit.py
```

1. Go to `[9] Set Global Info` and configure:
   - Output folder
   - Subnet for discovery

2. Use `[1] Discover Possible Subnets` to:
   - Run `masscan`, `nmap`, `netdiscover`, or `nbtscan`
   - Merge discovered subnets
   - View results

## 📁 Output Structure

```
output/
└── subnet-discover-phase/
    ├── 192.168.1.0_24/
    │   ├── masscan-out.txt
    │   ├── nmap-out.txt
    │   ├── unique-subnets-masscan.txt
    └── all-unique-subnets.txt
```

## 🧭 Status

Active work-in-progress tool. Features  Host Discovery and Enumeration phases are scaffolded but not yet implemented.

## 📄 License

MIT

# 🔍 Corporate Side Scanner

A Python-based corporate network scanning tool powered by **[RustScan](https://github.com/RustScan/RustScan)**.  
Scan multiple sites from structured text files, get per-site results and a combined overall report — all from a single command.

---

## 📋 Features

- 📁 **Folder mode** — point it at a directory of `SITENAME.txt` files and scan all sites automatically
- 🖥️ **Single mode** — scan individual IPs or CIDR ranges directly from the CLI
- 📊 **Per-site reports** — host count, open ports, and detected services per site
- 📈 **Global summary report** — aggregated results across all sites
- 💾 **JSON export** — one JSON file per site plus a combined `GLOBAL_REPORT` file
- 🚫 **Exclude addresses** — skip specific IPs or networks via `--exclude`
- 🎨 **Colored terminal output** — clear, readable scan progress and results

---

## ⚙️ Requirements

### Python
- Python **3.10** or newer
- No external Python packages required (standard library only)

### RustScan
This tool is built on top of **[RustScan](https://github.com/RustScan/RustScan)** — a modern, blazing-fast port scanner written in Rust that automatically pipes results into Nmap.

> ⚠️ Both **RustScan** and **Nmap** must be installed and available in your `PATH`.

#### Install RustScan

**Via cargo (recommended):**
```bash
cargo install rustscan
```

**Via .deb package (Debian/Ubuntu/Kali):**
```bash
# Download the latest .deb from https://github.com/RustScan/RustScan/releases
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb
sudo dpkg -i rustscan_amd64.deb
```

**Via Docker:**
```bash
docker pull rustscan/rustscan:latest
```

#### Install Nmap

```bash
# Debian/Ubuntu/Kali
sudo apt install nmap

# Arch
sudo pacman -S nmap

# Fedora/RHEL
sudo dnf install nmap
```

#### Verify installation
```bash
rustscan --version
nmap --version
```

---

## 📂 Input File Format

Place one `.txt` file per site in a folder. The filename (without extension) becomes the site name.

```
sites/
├── BERLIN.txt
├── HAMBURG.txt
├── MUENCHEN.txt
└── FRANKFURT.txt
```

Each file contains one IP address or CIDR network per line. Lines starting with `#` are treated as comments and ignored.

```
# BERLIN.txt
# Büronetz
192.168.10.0/24

# Server-VLAN
10.10.5.0/28

# Einzelner Host
172.16.0.50
```

---

## 🚀 Usage

### Folder mode — scan all sites

```bash
python Coperate_Side_Scanner.py folder /pfad/zu/sites/ --output ./berichte
```

### Single mode — scan specific targets

```bash
python Coperate_Side_Scanner.py single 192.168.1.0/24 10.0.0.5 --site BERLIN --output ./berichte
```

### Dry run — preview targets without scanning

```bash
python Coperate_Side_Scanner.py folder /pfad/zu/sites/ --dry-run
```

---

## 🔧 Options

All options are available in both `folder` and `single` mode.

| Option | Default | Description |
|---|---|---|
| `--output`, `-o` | — | Directory for JSON report export |
| `--exclude` | — | Comma-separated IPs/CIDRs to exclude (passed to RustScan `--exclude-addresses`) |
| `--ulimit` | `5000` | RustScan ulimit for file descriptors |
| `--batch-size` | `2500` | RustScan batch size (ports scanned simultaneously) |
| `--timeout` | `2000` | Port timeout in milliseconds |
| `--scan-timeout` | `3600` | Maximum total scan time per site in seconds |
| `--nmap-args` | — | Additional nmap arguments (passed after `--`) |
| `--dry-run` | — | Show targets without running a real scan |
| `--no-color` | — | Disable ANSI colors in terminal output |

### `single` mode only

| Option | Default | Description |
|---|---|---|
| `--site`, `-s` | `MANUAL` | Site name for the report |

---

## 💡 Examples

**Scan all sites, exclude gateway and management IPs:**
```bash
python Coperate_Side_Scanner.py folder ./sites \
  --output ./reports \
  --exclude 192.168.1.1,192.168.1.254,10.0.0.1
```

**Fast scan with higher ulimit and larger batch:**
```bash
python Coperate_Side_Scanner.py folder ./sites \
  --output ./reports \
  --ulimit 10000 \
  --batch-size 5000 \
  --timeout 1500
```

**Single site with additional nmap scripts:**
```bash
python Coperate_Side_Scanner.py single 10.10.0.0/24 \
  --site DATACENTER \
  --output ./reports \
  --nmap-args "-sC --script=banner"
```

**No color output (e.g. for logging to file):**
```bash
python Coperate_Side_Scanner.py folder ./sites --no-color --output ./reports | tee scan.log
```

---

## 📄 Output

### Terminal

The tool prints a colored summary per site during scanning and a final aggregated report at the end:

```
  ──────────────────────────────────────────────────────
  Site: BERLIN  |  Hosts found: 3

    192.168.10.5
      ● 22/tcp (ssh - OpenSSH 8.9)
      ● 80/tcp (http - nginx 1.22)

    192.168.10.12
      ● 443/tcp (https - Apache httpd 2.4)
      ● 3306/tcp (mysql - MySQL 8.0)

  Services at BERLIN:
    http                 ██ 2
    ssh                  █ 1
    https                █ 1
    mysql                █ 1
```

### JSON Export

For each site a file `SITENAME_TIMESTAMP.json` is created, plus a combined `GLOBAL_REPORT_TIMESTAMP.json`.

```
reports/
├── BERLIN_20240315_143022.json
├── HAMBURG_20240315_143022.json
├── MUENCHEN_20240315_143022.json
└── GLOBAL_REPORT_20240315_143022.json
```

**Global report structure:**
```json
{
  "generated_at": "2024-03-15T14:30:22",
  "total_sites": 3,
  "total_hosts": 12,
  "global_services": {
    "ssh": 8,
    "http": 5,
    "https": 4
  },
  "sites": [ ... ]
}
```

---

## ⚠️ Notes

- Scanning networks requires appropriate authorization. Only scan systems you own or have explicit permission to scan.
- RustScan requires **root/sudo** on some systems for certain scan types (e.g. SYN scans).
- Large networks with many hosts may require increasing `--ulimit` and `--scan-timeout`.

---

## 🔗 Links

- **RustScan** — [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan)
- **Nmap** — [https://nmap.org](https://nmap.org)

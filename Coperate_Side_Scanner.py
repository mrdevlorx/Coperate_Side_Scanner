#!/usr/bin/env python3
"""
Network Scanner Tool - Powered by RustScan
Scans IP networks from site-specific text files and generates reports per site and overall.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
#  ANSI Colors for terminal output
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"

    @staticmethod
    def disable():
        for attr in ["RESET","BOLD","RED","GREEN","YELLOW","BLUE","MAGENTA","CYAN","WHITE","GREY"]:
            setattr(C, attr, "")


def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════╗
║         NETWORK SCANNER  ·  powered by RustScan        ║
╚══════════════════════════════════════════════════════╝{C.RESET}
""")


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def log(msg: str, level: str = "info"):
    icons = {"info": f"{C.BLUE}[*]{C.RESET}", "ok": f"{C.GREEN}[+]{C.RESET}",
             "warn": f"{C.YELLOW}[!]{C.RESET}", "err": f"{C.RED}[✗]{C.RESET}",
             "scan": f"{C.MAGENTA}[►]{C.RESET}"}
    print(f"  {icons.get(level, '[?]')} {msg}")


def check_rustscan() -> bool:
    """Verify rustscan is installed and accessible."""
    try:
        result = subprocess.run(["rustscan", "--version"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            ver = result.stdout.strip().split("\n")[0]
            log(f"RustScan found: {C.GREEN}{ver}{C.RESET}", "ok")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    log("RustScan not found. Install via: cargo install rustscan", "err")
    return False


def parse_targets(filepath: Path) -> list[str]:
    """Parse IPs and CIDR networks from a .txt file (one per line, # comments ignored)."""
    ip_pattern = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?'
        r'|[0-9a-fA-F:]+(?:/\d{1,3})?)$'
    )
    targets = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if ip_pattern.match(entry):
                targets.append(entry)
            else:
                log(f"Skipping invalid entry: '{entry}'", "warn")
    return targets


def run_rustscan(targets: list[str], rustscan_opts: dict) -> dict:
    """
    Run rustscan against a list of targets.
    Returns parsed nmap XML data as a dict keyed by host IP.
    """
    if not targets:
        return {}

    # Build rustscan command
    # rustscan pipes into nmap; we capture nmap XML via -oX -
    addresses = ",".join(targets)
    cmd = [
        "rustscan",
        "-a", addresses,
        "--ulimit", str(rustscan_opts.get("ulimit", 5000)),
        "--batch-size", str(rustscan_opts.get("batch_size", 2500)),
        "--timeout", str(rustscan_opts.get("timeout", 2000)),
    ]

    # --exclude-addresses is a native RustScan flag, must come BEFORE --
    if rustscan_opts.get("exclude"):
        cmd += ["--exclude-addresses", rustscan_opts["exclude"]]

    cmd += [
        "--",            # everything after -- is passed to nmap
        "-sV",           # version detection
        "--open",        # only show open ports
        "-oX", "-",      # XML output to stdout
        "--host-timeout", "30s",
    ]

    if rustscan_opts.get("extra_nmap_args"):
        cmd.extend(rustscan_opts["extra_nmap_args"].split())

    log(f"Running: {C.GREY}{' '.join(cmd)}{C.RESET}", "scan")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=rustscan_opts.get("scan_timeout", 3600))
    except subprocess.TimeoutExpired:
        log("Scan timed out!", "err")
        return {}
    except FileNotFoundError:
        log("rustscan binary not found during scan execution.", "err")
        return {}

    if result.returncode not in (0, 1):
        log(f"rustscan exited with code {result.returncode}", "warn")
        if result.stderr:
            log(f"stderr: {result.stderr[:300]}", "warn")

    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_output: str) -> dict:
    """Parse nmap XML output and return structured host data."""
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        log("xml.etree.ElementTree not available", "err")
        return {}

    hosts = {}
    if not xml_output.strip():
        return hosts

    # Find the XML portion (rustscan may output text before the XML)
    xml_start = xml_output.find("<?xml")
    if xml_start == -1:
        # Try to find <nmaprun directly
        xml_start = xml_output.find("<nmaprun")
    if xml_start == -1:
        log("No nmap XML found in output", "warn")
        return hosts

    xml_data = xml_output[xml_start:]

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        log(f"XML parse error: {e}", "err")
        return hosts

    for host_el in root.findall("host"):
        # Only include hosts that are "up"
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Get IP address
        ip = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr")
                break
        if not ip:
            continue

        # Hostname
        hostnames = []
        for hn in host_el.findall(".//hostname"):
            name = hn.get("name")
            if name:
                hostnames.append(name)

        # Ports / services
        ports = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            service_info = {}
            if service_el is not None:
                service_info = {
                    "name":    service_el.get("name", "unknown"),
                    "product": service_el.get("product", ""),
                    "version": service_el.get("version", ""),
                    "extrainfo": service_el.get("extrainfo", ""),
                }
            ports.append({
                "port":     port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "state":    state_el.get("state"),
                "service":  service_info,
            })

        hosts[ip] = {
            "ip":        ip,
            "hostnames": hostnames,
            "ports":     ports,
        }

    return hosts


# ─────────────────────────────────────────────
#  Reporting
# ─────────────────────────────────────────────
def service_label(port: dict) -> str:
    svc = port.get("service", {})
    name = svc.get("name", "unknown")
    product = svc.get("product", "")
    version = svc.get("version", "")
    parts = [p for p in [product, version] if p]
    return f"{port['port']}/{port['protocol']} ({name}{' - ' + ' '.join(parts) if parts else ''})"


def build_site_report(site_name: str, targets: list[str], hosts: dict) -> dict:
    """Build a structured report for one site."""
    service_summary: dict[str, int] = {}
    for host in hosts.values():
        for port in host["ports"]:
            svc = port.get("service", {}).get("name", "unknown")
            service_summary[svc] = service_summary.get(svc, 0) + 1

    return {
        "site":            site_name,
        "targets_scanned": targets,
        "hosts_found":     len(hosts),
        "hosts":           hosts,
        "service_summary": service_summary,
        "scanned_at":      datetime.now().isoformat(),
    }


def print_site_report(report: dict):
    site = report["site"]
    print(f"\n{C.CYAN}{C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.BOLD}Site: {C.YELLOW}{site}{C.RESET}  |  Hosts found: {C.GREEN}{report['hosts_found']}{C.RESET}")
    print(f"{C.GREY}  Targets: {', '.join(report['targets_scanned'])}{C.RESET}")

    if not report["hosts"]:
        log("No live hosts found at this site.", "warn")
        return

    for ip, host in report["hosts"].items():
        hostnames = f"  ({', '.join(host['hostnames'])})" if host["hostnames"] else ""
        print(f"\n    {C.WHITE}{C.BOLD}{ip}{C.RESET}{C.GREY}{hostnames}{C.RESET}")
        for port in host["ports"]:
            print(f"      {C.GREEN}●{C.RESET} {service_label(port)}")

    if report["service_summary"]:
        print(f"\n  {C.BOLD}Services at {site}:{C.RESET}")
        for svc, count in sorted(report["service_summary"].items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 20)
            print(f"    {C.CYAN}{svc:<20}{C.RESET} {bar} {count}")


def print_global_report(site_reports: list[dict]):
    total_hosts = sum(r["hosts_found"] for r in site_reports)
    global_services: dict[str, int] = {}
    for r in site_reports:
        for svc, cnt in r["service_summary"].items():
            global_services[svc] = global_services.get(svc, 0) + cnt

    print(f"\n\n{C.MAGENTA}{C.BOLD}{'═'*54}")
    print(f"  GESAMTBERICHT  ·  {len(site_reports)} Standorte gescannt")
    print(f"{'═'*54}{C.RESET}")
    print(f"  {C.BOLD}Systeme gefunden gesamt: {C.GREEN}{total_hosts}{C.RESET}\n")

    # Per-site summary table
    print(f"  {C.BOLD}{'Standort':<20} {'Hosts':>6}{C.RESET}")
    print(f"  {'─'*28}")
    for r in site_reports:
        status = C.GREEN if r["hosts_found"] > 0 else C.GREY
        print(f"  {status}{r['site']:<20}{C.RESET} {r['hosts_found']:>6}")

    # Global service summary
    if global_services:
        print(f"\n  {C.BOLD}Services (gesamt):{C.RESET}")
        for svc, count in sorted(global_services.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)
            print(f"    {C.CYAN}{svc:<20}{C.RESET} {bar} {count}")

    print(f"\n{C.MAGENTA}{C.BOLD}{'═'*54}{C.RESET}\n")


def export_reports(site_reports: list[dict], output_dir: Path):
    """Export JSON reports per site and a combined global report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for report in site_reports:
        filename = output_dir / f"{report['site']}_{ts}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log(f"Site-Report exportiert: {C.WHITE}{filename}{C.RESET}", "ok")

    # Global report
    global_report = {
        "generated_at": datetime.now().isoformat(),
        "total_sites":  len(site_reports),
        "total_hosts":  sum(r["hosts_found"] for r in site_reports),
        "global_services": {},
        "sites": site_reports,
    }
    for r in site_reports:
        for svc, cnt in r["service_summary"].items():
            global_report["global_services"][svc] = (
                global_report["global_services"].get(svc, 0) + cnt
            )

    global_file = output_dir / f"GLOBAL_REPORT_{ts}.json"
    with open(global_file, "w", encoding="utf-8") as f:
        json.dump(global_report, f, indent=2, ensure_ascii=False)
    log(f"Gesamtbericht exportiert: {C.WHITE}{global_file}{C.RESET}", "ok")

    return global_file


# ─────────────────────────────────────────────
#  Core: Folder scan
# ─────────────────────────────────────────────
def scan_folder(folder: Path, output_dir: Optional[Path], rustscan_opts: dict,
                dry_run: bool = False):
    """Scan all .txt files in a folder, one file = one site."""
    txt_files = sorted(folder.glob("*.txt"))
    if not txt_files:
        log(f"Keine .txt-Dateien in '{folder}' gefunden.", "err")
        sys.exit(1)

    log(f"Standort-Dateien gefunden: {C.BOLD}{len(txt_files)}{C.RESET}", "ok")
    for f in txt_files:
        log(f"  {C.GREY}{f.name}{C.RESET}", "info")

    site_reports = []

    for txt_file in txt_files:
        site_name = txt_file.stem  # filename without extension
        targets = parse_targets(txt_file)

        if not targets:
            log(f"[{site_name}] Keine gültigen Ziele – überspringe.", "warn")
            empty_report = build_site_report(site_name, [], {})
            site_reports.append(empty_report)
            continue

        log(f"[{C.YELLOW}{site_name}{C.RESET}] {len(targets)} Ziel(e): {', '.join(targets)}", "scan")

        if dry_run:
            log("Dry-run – kein echter Scan.", "warn")
            hosts = {}
        else:
            hosts = run_rustscan(targets, rustscan_opts)

        report = build_site_report(site_name, targets, hosts)
        site_reports.append(report)
        print_site_report(report)

    print_global_report(site_reports)

    if output_dir:
        export_reports(site_reports, output_dir)
    else:
        log("Kein Output-Verzeichnis angegeben – kein Export.", "warn")


# ─────────────────────────────────────────────
#  Core: Single scan
# ─────────────────────────────────────────────
def scan_single(targets_raw: list[str], site_name: str,
                output_dir: Optional[Path], rustscan_opts: dict,
                dry_run: bool = False):
    """Scan a user-supplied list of targets (single site)."""
    log(f"Scanning site '{C.YELLOW}{site_name}{C.RESET}': {', '.join(targets_raw)}", "scan")

    if dry_run:
        hosts = {}
    else:
        hosts = run_rustscan(targets_raw, rustscan_opts)

    report = build_site_report(site_name, targets_raw, hosts)
    print_site_report(report)
    print_global_report([report])

    if output_dir:
        export_reports([report], output_dir)


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_scanner",
        description=(
            "Network Scanner powered by RustScan.\n"
            "Scannt IP-Netze aus Standort-TXT-Dateien und erstellt Berichte."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # Alle Standorte aus Ordner scannen und Berichte exportieren
  python network_scanner.py folder /pfad/zu/sites --output ./reports

  # Einzelne IPs / Netze scannen
  python network_scanner.py single 192.168.1.0/24 10.0.0.1 --site BERLIN --output ./reports

  # Nur anzeigen was gescannt würde (kein echter Scan)
  python network_scanner.py folder /pfad/zu/sites --dry-run
        """
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── folder sub-command ──
    folder_p = sub.add_parser("folder", help="Ordner mit SITENAME.txt Dateien scannen")
    folder_p.add_argument("path", type=Path, help="Pfad zum Ordner mit .txt Dateien")
    folder_p.add_argument("--output", "-o", type=Path, default=None,
                          help="Ausgabe-Verzeichnis für JSON-Berichte")

    # ── single sub-command ──
    single_p = sub.add_parser("single", help="Einzelne IPs / Netze direkt scannen")
    single_p.add_argument("targets", nargs="+", help="IP-Adressen oder CIDR-Netze")
    single_p.add_argument("--site", "-s", default="MANUAL",
                          help="Standortname (Standard: MANUAL)")
    single_p.add_argument("--output", "-o", type=Path, default=None,
                          help="Ausgabe-Verzeichnis für JSON-Berichte")

    # ── common options (both sub-commands) ──
    for p in [folder_p, single_p]:
        p.add_argument("--ulimit", type=int, default=5000,
                       help="RustScan ulimit (Standard: 5000)")
        p.add_argument("--batch-size", type=int, default=2500,
                       help="RustScan batch size (Standard: 2500)")
        p.add_argument("--timeout", type=int, default=2000,
                       help="RustScan port timeout in ms (Standard: 2000)")
        p.add_argument("--scan-timeout", type=int, default=3600,
                       help="Maximale Gesamtzeit pro Site in Sekunden (Standard: 3600)")
        p.add_argument("--exclude", type=str, default="",
                       metavar="ADDR",
                       help="Adressen/Netze von RustScan ausschließen, kommagetrennt "
                            "(z.B. '192.168.1.1,10.0.0.0/8')")
        p.add_argument("--nmap-args", type=str, default="",
                       help="Zusätzliche nmap-Argumente (in Anführungszeichen)")
        p.add_argument("--dry-run", action="store_true",
                       help="Kein echter Scan – nur Ziele anzeigen")
        p.add_argument("--no-color", action="store_true",
                       help="Keine ANSI-Farben in der Ausgabe")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    banner()

    if not check_rustscan():
        sys.exit(1)

    rustscan_opts = {
        "ulimit":          args.ulimit,
        "batch_size":      args.batch_size,
        "timeout":         args.timeout,
        "scan_timeout":    args.scan_timeout,
        "extra_nmap_args": args.nmap_args,
        "exclude":         args.exclude,
    }

    if args.command == "folder":
        folder = args.path
        if not folder.is_dir():
            log(f"'{folder}' ist kein gültiger Ordner.", "err")
            sys.exit(1)
        scan_folder(folder, args.output, rustscan_opts, dry_run=args.dry_run)

    elif args.command == "single":
        scan_single(args.targets, args.site, args.output,
                    rustscan_opts, dry_run=args.dry_run)


if __name__ == "__main__":
    main()

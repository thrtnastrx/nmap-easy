#!/usr/bin/env python3
"""
Nmap Menu CLI v0.2  (adds NSE script selection)

A terminal-based, user-friendly front-end for Nmap.
- Numbered menus for presets and options
- Live progress (uses --stats-every)
- Ctrl+C to stop scans cleanly
- Parses XML output to a readable table
- Export results to CSV and save raw XML
- NEW: NSE script selection
    * None, Default (-sC), Categories (multi-select), or specific script names
    * Categories discovered from `nmap --script-help all`

No external dependencies (stdlib only). Requires nmap installed.

Usage:
  python nmap-easy.py

Security/Ethics: Only scan systems you own or have permission to test.
"""
from __future__ import annotations

import csv
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Set
from xml.etree import ElementTree as ET

APP_VERSION = "0.2"

# ----------------------------- Presets -----------------------------
@dataclass
class ScanPreset:
    name: str
    description: str
    args: List[str]

PRESETS: List[ScanPreset] = [
    ScanPreset("Quick Scan", "Quick Scan", ["-sT", "-Pn"]),
    ScanPreset("Top 1000 TCP", "Default 1000 TCP ports, service version", ["-sT", "-sV", "-T4", "-Pn"]),
    ScanPreset("Full TCP", "All 65535 TCP ports (slower)", ["-sT", "-p", "1-65535", "-T3", "-Pn"]),
    ScanPreset("Top 100 UDP", "Top 100 UDP ports (slower & may require sudo)", ["-sU", "--top-ports", "100", "-T4", "-Pn"]),
    ScanPreset("Intense (TCP)", "T4, version, scripts", ["-sT", "-sV", "-A", "-T4", "-Pn"]),
]

TIMING = ["-T2", "-T3", "-T4", "-T5"]  # polite..insane

# ----------------------------- Utilities -----------------------------
def which(cmd: str) -> Optional[str]:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(path, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None

def parse_targets(text: str) -> List[str]:
    parts = re.split(r"[\s,]+", text.strip())
    return [p for p in parts if p]

# ----------------------------- Privilege Check Helper -----------------------------
def is_privileged() -> bool:
    """
    Returns True if we're running with privileges sufficient for raw packet scans
    (root/admin on Unix). On Windows, assume privileged since raw sockets behave differently.
    """
    try:
        return os.geteuid() == 0  # Unix/macOS
    except AttributeError:
        # No geteuid on Windows; nmap handles privileges differently there.
        return True

@dataclass
class ParsedHost:
    address: str
    hostname: str
    ports: List[Tuple[str, str, str]]

def parse_nmap_xml(xml_path: str) -> List[ParsedHost]:
    hosts: List[ParsedHost] = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addr_el = host.find("address[@addrtype='ipv4']") or host.find("address[@addrtype='ipv6']") or host.find("address")
            address = addr_el.get("addr") if addr_el is not None else "?"
            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else ""
            ports_list: List[Tuple[str, str, str]] = []
            for p in host.findall("ports/port"):
                proto = p.get("protocol", "?")
                portid = p.get("portid", "?")
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else "?"
                if state != "open":
                    continue
                svc_el = p.find("service")
                service = svc_el.get("name") if svc_el is not None else "?"
                product = (svc_el.get("product") or "") if svc_el is not None else ""
                version = (svc_el.get("version") or "") if svc_el is not None else ""
                extrainfo = (svc_el.get("extrainfo") or "") if svc_el is not None else ""
                svctext = service
                details = ", ".join([x for x in [product, version, extrainfo] if x])
                if details:
                    svctext += f" ({details})"
                ports_list.append((f"{portid}/{proto}", state, svctext))
            hosts.append(ParsedHost(address=address, hostname=hostname, ports=ports_list))
    except Exception as e:
        print(f"[!] XML parse error: {e}")
    return hosts

def print_table(rows: List[List[str]], headers: List[str] | None = None) -> None:
    cols = len(rows[0]) if rows else (len(headers) if headers else 0)
    widths = [0] * cols
    if headers:
        for i, h in enumerate(headers):
            widths[i] = max(widths[i], len(h))
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    def fmt_row(r: List[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r))
    if headers:
        print(fmt_row(headers))
        print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt_row(r))

# ----------------------------- NSE Discovery -----------------------------

# ----------------------------- Applications Catalog -----------------------------
from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class ApplicationEntry:
    name: str
    tcp_ports: str = ""  # e.g., "80,443,8000-8100"
    udp_ports: str = ""  # e.g., "53,67,500-510"

# Seed catalog with common apps
APP_CATALOG: List[ApplicationEntry] = [
    ApplicationEntry(name="DNS",  udp_ports="53"),
    ApplicationEntry(name="HTTP", tcp_ports="80"),
    ApplicationEntry(name="HTTPS", tcp_ports="443"),
    ApplicationEntry(name="FTP",  tcp_ports="21"),
]

def list_apps() -> List[str]:
    return [f"{i+1}. {e.name}  (TCP: {e.tcp_ports or '-'} | UDP: {e.udp_ports or '-'})" for i, e in enumerate(APP_CATALOG)]

def find_app_index(name: str) -> int:
    for i, e in enumerate(APP_CATALOG):
        if e.name.lower() == name.lower():
            return i
    return -1

def add_app_interactive():
    name = input("New application name: ").strip()
    if not name:
        print("[i] Name is required.")
        return
    if find_app_index(name) != -1:
        print("[i] An application with that name already exists.")
        return
    tcp = input("TCP ports for this app (comma/ranges or blank): ").strip()
    udp = input("UDP ports for this app (comma/ranges or blank): ").strip()
    try:
        tcp_n = normalize_port_list(tcp) if tcp else ""
        udp_n = normalize_port_list(udp) if udp else ""
    except ValueError as e:
        print(f"[i] {e}. App not added.")
        return
    APP_CATALOG.append(ApplicationEntry(name=name, tcp_ports=tcp_n, udp_ports=udp_n))
    print("[+] Application added.")

def edit_app_interactive():
    if not APP_CATALOG:
        print("[i] Catalog is empty.")
        return
    print("\nAvailable applications:")
    for line in list_apps():
        print("  " + line)
    sel = input("Enter number or name to edit: ").strip()
    idx = None
    if sel.isdigit():
        i = int(sel) - 1
        if 0 <= i < len(APP_CATALOG):
            idx = i
    if idx is None:
        idx = find_app_index(sel)
    if idx is None or idx < 0:
        print("[i] Not found.")
        return
    entry = APP_CATALOG[idx]
    print(f"Editing '{entry.name}' (leave blank to keep current)")
    new_name = input(f"Name [{entry.name}]: ").strip()
    tcp = input(f"TCP ports [{entry.tcp_ports or '-'}]: ").strip()
    udp = input(f"UDP ports [{entry.udp_ports or '-'}]: ").strip()
    if new_name:
        if find_app_index(new_name) not in (-1, idx):
            print("[i] Another app already has that name.")
        else:
            entry.name = new_name
    try:
        if tcp:
            entry.tcp_ports = normalize_port_list(tcp)
        if udp:
            entry.udp_ports = normalize_port_list(udp)
    except ValueError as e:
        print(f"[i] {e}. Changes not fully applied.")
    print("[+] Application updated.")

def delete_app_interactive():
    if not APP_CATALOG:
        print("[i] Catalog is empty.")
        return
    print("\nAvailable applications:")
    for line in list_apps():
        print("  " + line)
    sel = input("Enter number or name to delete: ").strip()
    idx = None
    if sel.isdigit():
        i = int(sel) - 1
        if 0 <= i < len(APP_CATALOG):
            idx = i
    if idx is None:
        idx = find_app_index(sel)
    if idx is None or idx < 0:
        print("[i] Not found.")
        return
    removed = APP_CATALOG.pop(idx)
    print(f"[+] Deleted application '{removed.name}'.")

def select_apps_interactive() -> Tuple[str, str]:
    """
    Returns aggregated (tcp_ports, udp_ports) from selected apps.
    """
    if not APP_CATALOG:
        print("[i] No applications defined yet.")
        return "", ""
    while True:
        print("\nApplications Menu")
        print("  1) Select applications to scan")
        print("  2) View applications list")
        print("  3) Add application")
        print("  4) Edit application")
        print("  5) Delete application")
        print("  6) Done / Back")
        choice = prompt_int("Select [1-6] (default 1):", 1, 6, default=1)
        if choice == 2:
            print("\nCurrent applications:")
            for line in list_apps():
                print("  " + line)
        elif choice == 3:
            add_app_interactive()
        elif choice == 4:
            edit_app_interactive()
        elif choice == 5:
            delete_app_interactive()
        elif choice == 6:
            # Done without selecting; return empty (caller decides)
            return "", ""
        else:  # select
            print("\nAvailable applications:")
            for line in list_apps():
                print("  " + line)
            raw = input("Enter numbers or names (comma-separated, ranges allowed for numbers): ").strip()
            if not raw:
                continue
            picks: List[int] = []
            # allow numeric ranges like 1-3 and comma-separated
            for token in raw.split(","):
                token = token.strip()
                m = re.match(r"^(\d+)-(\d+)$", token)
                if m:
                    a, b = int(m.group(1)), int(m.group(2))
                    if a <= b:
                        for i in range(a, b+1):
                            if 1 <= i <= len(APP_CATALOG):
                                picks.append(i)
                elif token.isdigit():
                    i = int(token)
                    if 1 <= i <= len(APP_CATALOG):
                        picks.append(i)
                else:
                    # treat as name
                    idx = find_app_index(token)
                    if idx >= 0:
                        picks.append(idx + 1)
            if not picks:
                print("[i] No valid selections.")
                continue
            tcp_all: List[str] = []
            udp_all: List[str] = []
            for i in sorted(set(picks)):
                entry = APP_CATALOG[i - 1]
                if entry.tcp_ports:
                    tcp_all.append(entry.tcp_ports)
                if entry.udp_ports:
                    udp_all.append(entry.udp_ports)
            tcp_join = ",".join(tcp_all) if tcp_all else ""
            udp_join = ",".join(udp_all) if udp_all else ""
            # Normalize merged lists to validate formatting
            try:
                tcp_join = normalize_port_list(tcp_join) if tcp_join else ""
                udp_join = normalize_port_list(udp_join) if udp_join else ""
            except ValueError as e:
                print(f"[i] {e}. Please re-select.")
                continue
            return tcp_join, udp_join
def discover_nse_categories(max_lines: int = 500000) -> List[str]:
    try:
        proc = subprocess.run(
            ["nmap", "--script-help", "all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        cats: Set[str] = set()
        lines = proc.stdout.splitlines()[:max_lines]
        for line in lines:
            if "Categories:" in line:
                frag = line.split("Categories:", 1)[1]
                for c in re.split(r"[\s,]+", frag.strip()):
                    c = c.strip().lower()
                    if c and re.match(r"^[a-z0-9_-]+$", c):
                        cats.add(c)
        out = sorted(cats)
        preferred = ["safe","default","discovery","version","vuln","auth","brute","intrusive","malware","broadcast","exploit"]
        ordered = [c for c in preferred if c in out] + [c for c in out if c not in preferred]
        return ordered
    except Exception:
        return ["safe","default","discovery","version","vuln","auth","brute","intrusive","malware","broadcast","exploit","external","dos","fuzzer"]

# ----------------------------- Interactive Config -----------------------------
@dataclass
class Config:
    targets: List[str] = field(default_factory=list)
    preset_idx: int = 0
    add_sV: bool = False
    add_sC: bool = False
    add_O: bool = False
    timing_idx: int = 1
    top_ports_override: int = 0
    script_mode: str = "none"
    script_categories: List[str] = field(default_factory=list)
    script_names: List[str] = field(default_factory=list)
    custom_ports_tcp: str = ""
    custom_ports_udp: str = ""
    use_custom_ports: bool = False
    selected_applications: List[str] = field(default_factory=list)

def prompt_int(prompt: str, lo: int, hi: int, default: Optional[int] = None) -> int:
    while True:
        s = input(f"{prompt} ").strip()
        if not s and default is not None:
            return default
        if s.isdigit():
            v = int(s)
            if lo <= v <= hi:
                return v
        print(f"Enter a number between {lo} and {hi} (or press Enter for default).")

def yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        s = input(f"{prompt} {suffix} ").strip().lower()
        if not s:
            return default
        if s in ("y", "yes"):
            return True
        if s in ("n", "no"):
            return False
        print("Please answer y or n.")

def prompt_multi_select(options: List[str]) -> List[int]:
    print("Enter numbers (e.g., 1,3,5 or 2-4). Press Enter to finish.")
    raw = input("Selection: ").strip()
    if not raw:
        return []
    picked: Set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        m = re.match(r"^(\d+)-(\d+)$", token)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a <= b:
                for i in range(a, b+1):
                    if 1 <= i <= len(options):
                        picked.add(i)
            continue
        if token.isdigit():
            i = int(token)
            if 1 <= i <= len(options):
                picked.add(i)
    return sorted(picked)

# Helper to validate/compress user-entered port lists
def normalize_port_list(s: str) -> str:
    """
    Accepts a comma-separated list of ports and ranges (e.g., 22,80,8000-8100)
    Returns a cleaned string with only digits, commas, and hyphens; removes spaces.
    Raises ValueError if the format is clearly invalid.
    """
    s = s.strip().replace(" ", "")
    if not s:
        return ""
    # Allowed pattern: numbers and ranges separated by commas
    if not re.fullmatch(r"(\d+(-\d+)?)(,(\d+(-\d+)?))*", s):
        raise ValueError("Invalid port list format. Use numbers and ranges like 22,80,8000-8100")
    # Basic numeric sanity: each number 1..65535 and ranges a<=b
    for token in s.split(","):
        if "-" in token:
            a, b = token.split("-", 1)
            a_i, b_i = int(a), int(b)
            if not (1 <= a_i <= 65535 and 1 <= b_i <= 65535 and a_i <= b_i):
                raise ValueError("Port ranges must be within 1-65535 and a<=b")
        else:
            v = int(token)
            if not (1 <= v <= 65535):
                raise ValueError("Ports must be within 1-65535")
    return s

def build_command(cfg: Config) -> Tuple[List[str], str]:
    tmpdir = tempfile.mkdtemp(prefix="nmap_cli_")
    xml_path = os.path.join(tmpdir, "scan.xml")

    preset = PRESETS[cfg.preset_idx]
    args = list(preset.args)

    if cfg.add_sV and "-sV" not in args:
        args += ["-sV"]
    if cfg.add_sC and "-sC" not in args and "-A" not in args:
        args += ["-sC"]
    if cfg.add_O and "-O" not in args:
        args += ["-O"]

    if cfg.script_mode == "default":
        if "-sC" not in args and "-A" not in args:
            args += ["-sC"]
    elif cfg.script_mode == "categories" and cfg.script_categories:
        args += ["--script", ",".join(cfg.script_categories)]
    elif cfg.script_mode == "names" and cfg.script_names:
        args += ["--script", ",".join(cfg.script_names)]

    # If not running as root/admin, downgrade scans that require raw sockets
    if not is_privileged():
        # UDP scan requires root on Unix/macOS
        if "-sU" in args:
            print("[i] Not running as root: UDP scan (-sU) requires elevated privileges. Removing -sU and any UDP port specs.")
            args = [a for a in args if a != "-sU"]
            # Strip UDP specs from '-p' if present (U:...)
            if "-p" in args:
                try:
                    p_idx = args.index("-p")
                    if p_idx + 1 < len(args):
                        spec = args[p_idx + 1]
                        parts = [part for part in spec.split(",") if not part.startswith("U:")]
                        if parts:
                            args[p_idx + 1] = ",".join(parts)
                        else:
                            # remove -p and its arg entirely if now empty
                            del args[p_idx:p_idx + 2]
                except ValueError:
                    pass
        # SYN scan requires root; fall back to TCP connect
        if "-sS" in args:
            print("[i] Not running as root: SYN scan (-sS) requires elevated privileges. Switching to connect scan (-sT).")
            args = [a for a in args if a != "-sS"]
            if "-sT" not in args:
                args.insert(0, "-sT")
        # OS detection typically needs root
        if "-O" in args:
            print("[i] Not running as root: OS detection (-O) may require elevated privileges. Removing -O.")
            args = [a for a in args if a != "-O"]

    # Handle custom ports: remove preset-specified ports and top-ports if overriding
    if cfg.use_custom_ports and (cfg.custom_ports_tcp or cfg.custom_ports_udp):
        cleaned = []
        skip_next = False
        i = 0
        while i < len(args):
            a = args[i]
            if skip_next:
                skip_next = False
                i += 1
                continue
            if a in ("-p", "--top-ports"):
                # skip this and its argument
                skip_next = True
                i += 1
                i += 1
                continue
            cleaned.append(a)
            i += 1
        args = cleaned

        port_specs = []
        if cfg.custom_ports_tcp:
            port_specs.append(f"T:{cfg.custom_ports_tcp}")
            # ensure a TCP scan type is present (add -sT if neither -sS nor -sT present)
            if not any(x in args for x in ("-sS", "-sT")):
                args.insert(0, "-sT")
        if cfg.custom_ports_udp:
            if is_privileged():
                port_specs.append(f"U:{cfg.custom_ports_udp}")
                # ensure UDP scan is enabled
                if "-sU" not in args:
                    args.insert(0, "-sU")
            else:
                print("[i] Not running as root: ignoring custom UDP ports. Run with sudo to scan UDP.")
        if port_specs:
            args += ["-p", ",".join(port_specs)]

        # Final safety: if not privileged, strip any UDP remnants added above
        if not is_privileged():
            if "-sU" in args:
                args = [a for a in args if a != "-sU"]
            if "-p" in args:
                try:
                    p_idx = args.index("-p")
                    if p_idx + 1 < len(args):
                        spec = args[p_idx + 1]
                        parts = [part for part in spec.split(",") if not part.startswith("U:")]
                        if parts:
                            args[p_idx + 1] = ",".join(parts)
                        else:
                            del args[p_idx:p_idx + 2]
                except ValueError:
                    pass

    t = TIMING[cfg.timing_idx] if 0 <= cfg.timing_idx < len(TIMING) else "-T3"
    args += [t]

    # Only add --top-ports if not using custom ports
    if cfg.top_ports_override > 0 and not cfg.use_custom_ports:
        cleaned = []
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a == "--top-ports":
                skip_next = True
                continue
            cleaned.append(a)
        args = cleaned + ["--top-ports", str(cfg.top_ports_override)]

    args += ["--stats-every", "2s", "-oX", xml_path]
    cmd = ["nmap"] + args + cfg.targets
    return cmd, xml_path

def run_scan(cmd: List[str], xml_path: str) -> int:
    print("\n[>] Running:", " ".join(shlex.quote(c) for c in cmd))
    print("[i] Press Ctrl+C to stop.\n")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("[!] nmap not found in PATH. Install Nmap and try again.")
        return 127
    except Exception as e:
        print(f"[!] Failed to start nmap: {e}")
        return 1

    exit_code = 1
    try:
        while True:
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                err = proc.stderr.read() if proc.stderr else ""
                if out:
                    for l in out.splitlines():
                        print(f"[o] {l}")
                if err:
                    for l in err.splitlines():
                        print(f"[e] {l}")
                break
            if proc.stdout and not proc.stdout.closed:
                line = proc.stdout.readline()
                if line:
                    print(f"[o] {line.rstrip()}")
            if proc.stderr and not proc.stderr.closed:
                line = proc.stderr.readline()
                if line:
                    print(f"[e] {line.rstrip()}")
            time.sleep(0.05)
        exit_code = proc.returncode or 0
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected, stopping scan...")
        try:
            proc.terminate()
        except Exception:
            pass
        exit_code = 130
    return exit_code

def export_csv(hosts: List[ParsedHost], path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Host", "Hostname", "Open Port", "Service/Version"])
        for h in hosts:
            if h.ports:
                for port, state, service in h.ports:
                    w.writerow([h.address, h.hostname, port, service])
            else:
                w.writerow([h.address, h.hostname, "-", "No open ports found"])

def show_results(hosts: List[ParsedHost]) -> None:
    rows: List[List[str]] = []
    for h in hosts:
        if h.ports:
            for port, state, service in h.ports:
                rows.append([h.address, h.hostname, port, service])
        else:
            rows.append([h.address, h.hostname, "-", "No open ports found"])
    if not rows:
        print("\n[=] No results parsed.")
        return
    print("\n[=] Results")
    print_table(rows, headers=["Host", "Hostname", "Open Port", "Service/Version"])

def main() -> None:
    if not which("nmap"):
        print("[!] Nmap not found in PATH. Install it from https://nmap.org/download.html and try again.")
        sys.exit(127)

    cfg = Config()

    print(f"Nmap Menu CLI v{APP_VERSION}")
    print("---------------------------------")

    while not cfg.targets:
        t = input("Enter targets (IP/hostname/CIDR, comma or space separated): ").strip()
        cfg.targets = parse_targets(t)
        if not cfg.targets:
            print("Please enter at least one target.")

    print("\nChoose a preset:")
    for i, p in enumerate(PRESETS, 1):
        print(f"  {i}. {p.name} - {p.description}")
    cfg.preset_idx = prompt_int(f"Select [1-{len(PRESETS)}] (default 1):", 1, len(PRESETS), default=1) - 1

    # If Quick Scan is selected, offer a submenu for Top 100, Custom Ports, or Applications
    if cfg.preset_idx == 0:
        print("\nQuick Scan options:")
        print("  1. Top 100 ports")
        print("  2. Custom ports")
        print("  3. Applications")
        qs_choice = prompt_int("Select [1-3] (default 1):", 1, 3, default=1)
        if qs_choice == 1:
            # Use Top 100 ports for Quick Scan
            cfg.use_custom_ports = False
            cfg.custom_ports_tcp = ""
            cfg.custom_ports_udp = ""
            cfg.top_ports_override = 100
        elif qs_choice == 3:
            # Applications selection path
            tcp_sel, udp_sel = select_apps_interactive()
            if not tcp_sel and not udp_sel:
                print("[i] No applications selected. Falling back to Top 100 ports.")
                cfg.use_custom_ports = False
                cfg.custom_ports_tcp = ""
                cfg.custom_ports_udp = ""
                cfg.top_ports_override = 100
            else:
                cfg.custom_ports_tcp = tcp_sel
                cfg.custom_ports_udp = udp_sel
                # If UDP selected but not privileged, prompt user
                if cfg.custom_ports_udp and not is_privileged():
                    print("\n[i] UDP scanning requires root/admin privileges on this system.")
                    print("You selected applications that include UDP ports, but are not running as root.")
                    print("Options:")
                    print("  1. Continue without UDP ports (TCP only)")
                    print("  2. Abort and re-run with sudo to include UDP")
                    udp_choice = prompt_int("Select [1-2] (default 1):", 1, 2, default=1)
                    if udp_choice == 1:
                        cfg.custom_ports_udp = ""
                    else:
                        print("[!] Aborting at user request to allow restart with sudo.")
                        sys.exit(1)
                cfg.use_custom_ports = bool(cfg.custom_ports_tcp or cfg.custom_ports_udp)
                if cfg.use_custom_ports:
                    cfg.top_ports_override = 0
        else:
            # Custom ports submenu (TCP/UDP lists)
            print("\nCustom Ports:")
            print("  1. TCP list")
            print("  2. UDP list")
            print("  3. TCP and UDP lists")
            cp_choice = prompt_int("Select [1-3] (default 1):", 1, 3, default=1)
            if cp_choice in (1, 3):
                tcp_raw = input("Enter TCP ports (e.g., 22,80,8000-8100): ").strip()
                if tcp_raw:
                    try:
                        cfg.custom_ports_tcp = normalize_port_list(tcp_raw)
                    except ValueError as e:
                        print(f"[i] {e}. Ignoring TCP custom ports.")
                        cfg.custom_ports_tcp = ""
            if cp_choice in (2, 3):
                udp_raw = input("Enter UDP ports (e.g., 53,67,500-510): ").strip()
                if udp_raw:
                    try:
                        cfg.custom_ports_udp = normalize_port_list(udp_raw)
                    except ValueError as e:
                        print(f"[i] {e}. Ignoring UDP custom ports.")
                        cfg.custom_ports_udp = ""
            # Privilege check for UDP custom ports before setting use_custom_ports
            if cfg.custom_ports_udp and not is_privileged():
                print("\n[i] UDP scanning requires root/admin privileges on this system.")
                print("You entered UDP ports, but are not running as root.")
                print("Options:")
                print("  1. Continue without UDP ports (TCP only)")
                print("  2. Abort and re-run with sudo to include UDP")
                udp_choice = prompt_int("Select [1-2] (default 1):", 1, 2, default=1)
                if udp_choice == 1:
                    cfg.custom_ports_udp = ""
                else:
                    print("[!] Aborting at user request to allow restart with sudo.")
                    sys.exit(1)
            cfg.use_custom_ports = bool(cfg.custom_ports_tcp or cfg.custom_ports_udp)
            if cfg.use_custom_ports:
                # When using custom ports, ignore any top-ports override
                cfg.top_ports_override = 0

    print("\nOptional flags:")
    cfg.add_sV = yes_no("Add service/version detection (-sV)?", default=False)
    cfg.add_sC = yes_no("Add default scripts (-sC)?", default=False)
    cfg.add_O  = yes_no("Add OS detection (-O)? (may need sudo)", default=False)

    print("\nNSE Scripts:")
    print("  1. None")
    print("  2. Default scripts (-sC)")
    print("  3. Choose categories (multi-select)")
    print("  4. Enter script names (comma-separated)")
    choice = prompt_int("Select [1-4] (default 1):", 1, 4, default=1)
    if choice == 2:
        cfg.script_mode = "default"
    elif choice == 3:
        cfg.script_mode = "categories"
        cats = discover_nse_categories()
        if cats:
            print("\nAvailable categories:")
            for i, c in enumerate(cats, 1):
                print(f"  {i}. {c}")
            idxs = prompt_multi_select(cats)
            cfg.script_categories = [cats[i-1] for i in idxs]
            if not cfg.script_categories:
                print("[i] No categories selected; continuing without category scripts.")
                cfg.script_mode = "none"
        else:
            print("[i] Could not discover categories; skipping.")
            cfg.script_mode = "none"
    elif choice == 4:
        cfg.script_mode = "names"
        names_raw = input("Enter script names (e.g., http-enum,ftp-anon): ").strip()
        if names_raw:
            cfg.script_names = [n.strip() for n in names_raw.split(",") if n.strip()]
        if not cfg.script_names:
            print("[i] No script names entered; continuing without custom scripts.")
            cfg.script_mode = "none"
    else:
        cfg.script_mode = "none"

    print("\nTiming templates:")
    for i, t in enumerate(TIMING, 1):
        print(f"  {i}. {t}{' (default)' if i == 2 else ''}")
    cfg.timing_idx = prompt_int("Select [1-4] (default 2):", 1, 4, default=2) - 1

    tp_raw = input("\nOverride top-ports (1-65535, Enter to skip): ").strip()
    if tp_raw:
        try:
            tp = int(tp_raw)
            if 1 <= tp <= 65535:
                cfg.top_ports_override = tp
        except ValueError:
            pass

    if not yes_no("\nOnly scan systems you own or have permission to test. Proceed?", default=True):
        print("Aborted.")
        sys.exit(0)

    cmd, xml_path = build_command(cfg)
    code = run_scan(cmd, xml_path)

    hosts: List[ParsedHost] = []
    if code == 0 and os.path.exists(xml_path):
        hosts = parse_nmap_xml(xml_path)
        show_results(hosts)
        print(f"\n[i] Parsed {len(hosts)} host(s) from: {xml_path}")
    else:
        print("\n[!] Scan did not complete successfully.")

    if hosts:
        if yes_no("\nSave results to CSV?", default=True):
            out = input("CSV path (default ./nmap_results.csv): ").strip() or "./nmap_results.csv"
            try:
                export_csv(hosts, out)
                print(f"[+] Saved CSV -> {out}")
            except Exception as e:
                print(f"[!] Failed to save CSV: {e}")
        if yes_no("Save raw XML?", default=False):
            out = input("XML path (default ./scan.xml): ").strip() or "./scan.xml"
            try:
                with open(xml_path, "rb") as src, open(out, "wb") as dst:
                    dst.write(src.read())
                print(f"[+] Saved XML -> {out}")
            except Exception as e:
                print(f"[!] Failed to save XML: {e}")
        print("\nDone. Goodbye.")

if __name__ == "__main__":
    main()
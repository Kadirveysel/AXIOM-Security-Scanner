#!/usr/bin/env python3
"""
AXIOM SECURITY SCANNER v2.1
Author: Plansmight (Kadir Veysel Sayar)
Description: Mathematical Precision Security Scanner with Enhanced UI.

Use only against systems you own or are explicitly authorized to test.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import threading
from datetime import datetime
from queue import Queue

VERSION = "2.1"
DEFAULT_TARGET = "scanme.nmap.org"
DEFAULT_PORTS = "1-1000"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 0.5
DEFAULT_RETRIES = 1

# Ports that get an active HTTP(S) probe instead of a passive banner read.
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
HTTPS_PORTS = {443, 8443}
BANNER_WIDTH = 90

# Enable ANSI escape sequences on Windows terminals (no-op elsewhere).
if os.name == "nt":
    os.system("")


# --- RENK KODLARI (ANSI) ---
class Colors:
    GREEN = "\033[92m"
    GREY = "\033[90m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"


def print_banner():
    banner = f"""{Colors.CYAN}
     █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ███╗
    ██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗ ████║
    ███████║ ╚███╔╝ ██║██║   ██║██╔████╔██║
    ██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╔╝██║
    ██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ v{VERSION}
    {Colors.RESET}{Colors.GREY}Mathematical Precision Security Scanner{Colors.RESET}
    {Colors.GREY}Authored by: Plansmight{Colors.RESET}
    """
    print(banner)


# --- ARGUMAN ISLEME ---
def parse_ports(spec):
    """Turn '1-1000', '22,80,443' or '1-100,443' into a sorted list of ports."""
    ports = set()
    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start, end = (int(x) for x in part.split("-", 1))
                if start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid port specification '{spec}' (examples: 1-1000, 22,80,443)"
        )
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return sorted(ports)


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number")
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def non_negative_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number")
    if number < 0:
        raise argparse.ArgumentTypeError("value must be 0 or more")
    return number


def positive_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number")
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return number


def parse_args():
    parser = argparse.ArgumentParser(
        description="AXIOM - Mathematical Precision Security Scanner",
        epilog="Authorized testing only. Always get permission before scanning.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="IP or hostname (omit to use the interactive prompt)",
    )
    parser.add_argument(
        "-p", "--ports",
        type=parse_ports,
        default=parse_ports(DEFAULT_PORTS),
        metavar="SPEC",
        help=f"ports to scan, e.g. 1-1000 or 22,80,443 (default: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "-t", "--threads",
        type=positive_int,
        default=DEFAULT_THREADS,
        help=f"number of worker threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=DEFAULT_RETRIES,
        help=f"extra attempts for ports that time out (default: {DEFAULT_RETRIES}, 0 = fastest)",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="passive mode: never send HTTP requests, only read banners services announce",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="save results to FILE as JSON without asking (default: ask after the scan)",
    )
    return parser.parse_args()


# --- GIRIS EKRANI (INPUT UI) ---
def prompt_target():
    """Kali Linux style interactive prompt. Enter selects the default target."""
    try:
        print(
            f"{Colors.CYAN}┌──( {Colors.BOLD}SET TARGET{Colors.RESET}{Colors.CYAN} )"
            f"─[ {Colors.GREY}Press Enter for '{DEFAULT_TARGET}'{Colors.RESET}{Colors.CYAN} ]"
        )
        user_input = input(f"└─► {Colors.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)

    if not user_input:
        print(f"{Colors.YELLOW}    └──> Default target selected.{Colors.RESET}")
        return DEFAULT_TARGET
    return user_input


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n{Colors.RED}[!] Error: Hostname could not be resolved.{Colors.RESET}")
        sys.exit(1)
    print(
        f"{Colors.GREEN}    └──> Target Locked: {Colors.BOLD}{target}{Colors.RESET}"
        f"{Colors.GREEN} ({ip}){Colors.RESET}"
    )
    return ip


# --- TARAMA ---
def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def sanitize(text, limit=BANNER_WIDTH):
    """Banners come from the remote host, so never print them raw: control
    characters (e.g. ANSI escape sequences) could manipulate the terminal."""
    clean = "".join(ch if ch.isprintable() else "." for ch in text)
    return clean[:limit]


def grab_banner(sock):
    """Read what the service announces on connect (SSH, FTP, SMTP, ...).
    Services that wait for the client to speak first (e.g. HTTP) return nothing."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(1024)
    except OSError:  # includes socket.timeout
        return "No banner"
    lines = data.decode("utf-8", errors="replace").strip().splitlines()
    if not lines:
        return "No banner"
    return sanitize(lines[0])


def http_probe(sock, host, use_tls, timeout=2.0):
    """Send a minimal HEAD request and report what the server says about itself.
    The Server header is the server's own claim and may be hidden or spoofed."""
    conn = sock
    tls_version = None
    try:
        sock.settimeout(timeout)
        if use_tls:
            # Certificate verification is intentionally off: the scanner only reads
            # response headers and has to work against self-signed hosts too.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(sock, server_hostname=host)
            tls_version = conn.version()

        request = (
            f"HEAD / HTTP/1.0\r\nHost: {sanitize(host, 255)}\r\n"
            f"User-Agent: AXIOM/{VERSION}\r\nConnection: close\r\n\r\n"
        )
        conn.sendall(request.encode("ascii", errors="replace"))

        response = b""
        while b"\n\n" not in response and b"\r\n\r\n" not in response and len(response) < 4096:
            chunk = conn.recv(1024)
            if not chunk:
                break
            response += chunk
    except ssl.SSLError:  # must come before OSError (it is a subclass)
        return "TLS handshake failed"
    except OSError:  # includes socket.timeout
        return "No response"
    finally:
        if conn is not sock:
            conn.close()

    lines = response.decode("iso-8859-1").splitlines()
    status = lines[0].strip() if lines else ""
    if not status:
        return "No response"
    if not status.startswith("HTTP/"):
        return sanitize(f"Non-HTTP reply: {status}")

    server = "not disclosed"
    for line in lines[1:]:
        if not line.strip():
            break  # end of headers
        name, _, value = line.partition(":")
        if name.strip().lower() == "server" and value.strip():
            server = value.strip()
            break

    parts = [status, f"Server: {server}"]
    if tls_version:
        parts.insert(0, tls_version)
    return sanitize(" | ".join(parts))


class Scanner:
    def __init__(self, target, ip, ports, threads, timeout, probe=True, retries=DEFAULT_RETRIES):
        self.target = target
        self.ip = ip
        self.ports = ports
        self.total = len(ports)
        self.threads = min(threads, self.total)
        self.timeout = timeout
        self.probe = probe
        self.retries = retries
        self.queue = Queue()
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.scanned = 0
        self.results = []  # open ports: (port, service, banner)
        self.counts = {"open": 0, "closed": 0, "filtered": 0}

    def identify(self, sock, port):
        if self.probe:
            if port in HTTPS_PORTS:
                return http_probe(sock, self.target, use_tls=True)
            if port in HTTP_PORTS:
                return http_probe(sock, self.target, use_tls=False)
        return grab_banner(sock)

    def scan_port(self, port):
        """Classify a port as open, closed (actively refused) or filtered
        (no answer: usually a firewall dropping packets). Only timeouts are
        retried, a refusal is a definitive answer."""
        state = "filtered"
        try:
            for _ in range(self.retries + 1):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    try:
                        sock.connect((self.ip, port))
                    except ConnectionRefusedError:
                        state = "closed"
                        break
                    except socket.timeout:
                        continue  # no answer yet: try again
                    except OSError:
                        break  # unreachable / reset: retrying will not help

                    state = "open"
                    banner = self.identify(sock, port)
                    service = service_name(port)
                    with self.lock:
                        self.results.append((port, service, banner))
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        print(
                            f"{Colors.GREEN} [+] {port:<6} | {Colors.BOLD}OPEN"
                            f"{Colors.RESET}{Colors.GREEN} | {service:<12} | {banner}{Colors.RESET}"
                        )
                    break
        except OSError:
            pass  # e.g. could not create a socket: leave the port as filtered
        finally:
            with self.lock:
                self.counts[state] += 1
                self.scanned += 1

    def worker(self):
        while True:
            port = self.queue.get()
            try:
                self.scan_port(port)
            finally:
                self.queue.task_done()

    def ui_monitor(self):
        bar_length = 30
        while not self.done.is_set():
            with self.lock:
                scanned = self.scanned
                percent = min(scanned / self.total * 100, 100)
                filled = min(bar_length * scanned // self.total, bar_length)
                bar = (
                    Colors.CYAN + "█" * filled
                    + Colors.GREY + "-" * (bar_length - filled)
                    + Colors.RESET
                )
                sys.stdout.write(
                    f"\r{Colors.YELLOW}[*] Calculating:{Colors.RESET} |{bar}| "
                    f"{scanned}/{self.total} ({percent:.0f}%)"
                )
                sys.stdout.flush()
            if scanned >= self.total:
                break
            self.done.wait(0.1)

    def run(self):
        for _ in range(self.threads):
            threading.Thread(target=self.worker, daemon=True).start()

        monitor = threading.Thread(target=self.ui_monitor, daemon=True)
        monitor.start()

        for port in self.ports:
            self.queue.put(port)

        self.queue.join()
        self.done.set()
        monitor.join()


# --- JSON CIKTISI ---
def build_report(scanner, start_time, end_time):
    return {
        "tool": "AXIOM",
        "version": VERSION,
        "target": scanner.target,
        "ip": scanner.ip,
        "mode": "active" if scanner.probe else "passive",
        "started": start_time.isoformat(timespec="seconds"),
        "finished": end_time.isoformat(timespec="seconds"),
        "duration_seconds": round((end_time - start_time).total_seconds(), 3),
        "ports_scanned": scanner.total,
        "summary": dict(scanner.counts),
        "open_ports": [
            {"port": port, "service": service, "banner": banner}
            for port, service, banner in sorted(scanner.results)
        ],
        "notice": "Banners and Server headers are reported by the remote host and are not verified.",
    }


def default_filename(target, when):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    return f"axiom_{safe}_{when:%Y%m%d_%H%M%S}.json"


def unique_path(path):
    """Never overwrite a file the user did not explicitly point us at."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    counter = 1
    while os.path.exists(f"{base}_{counter}{ext}"):
        counter += 1
    return f"{base}_{counter}{ext}"


def ask_save_json(default_name):
    """Ask after the scan whether to save a JSON report. Returns a path or None."""
    try:
        answer = input(f"{Colors.CYAN}Save results as JSON? [y/N]: {Colors.RESET}").strip().lower()
        if answer not in ("y", "yes", "e", "evet"):
            return None
        name = input(f"{Colors.CYAN}Filename [{default_name}]: {Colors.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None
    return unique_path(name or default_name)


def save_json(report, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def print_header(start_time, probe):
    mode = "active (HTTP/HTTPS probe)" if probe else "passive (banner read only)"
    print(f"\n{Colors.GREY}Computation Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.GREY}Mode: {mode}{Colors.RESET}")
    print("-" * 65)
    print(f"{Colors.BOLD} PORT   | STATUS | SERVICE      | BANNER{Colors.RESET}")
    print("-" * 65)


def print_summary(scanner, duration):
    sys.stdout.write("\r" + " " * 80 + "\r")
    print("-" * 65)
    print(f"{Colors.CYAN}AXIOM ANALYSIS COMPLETE{Colors.RESET}")
    if scanner.results:
        print(f"{Colors.BOLD}Open ports (sorted):{Colors.RESET}")
        for port, service, banner in sorted(scanner.results):
            print(f"  {Colors.GREEN}{port:<6}{Colors.RESET} {service:<12} {banner}")
        print(f"{Colors.GREY}Banners and Server headers are reported by the remote host, not verified.{Colors.RESET}")
    counts = scanner.counts
    print(f"Total Open Ports : {Colors.GREEN}{counts['open']}{Colors.RESET}")
    print(f"Port States      : open {counts['open']} | closed {counts['closed']} | filtered {counts['filtered']}")
    print(f"Time Elapsed     : {duration}")
    print("-" * 65 + "\n")


def main():
    args = parse_args()
    print_banner()

    target = args.target or prompt_target()
    ip = resolve_target(target)

    probe = not args.no_probe
    scanner = Scanner(target, ip, args.ports, args.threads, args.timeout, probe, args.retries)

    start_time = datetime.now()
    print_header(start_time, probe)

    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.done.set()
        print(f"\n\n{Colors.RED}[!] Process Interrupted.{Colors.RESET}")
        sys.exit(130)

    end_time = datetime.now()
    print_summary(scanner, end_time - start_time)

    # JSON output is opt-in: --json FILE saves directly, otherwise ask at the end,
    # but only when a person is at the keyboard (never hang a script or a pipe).
    path = None
    if args.json:
        path = args.json
    elif sys.stdin.isatty():
        path = ask_save_json(default_filename(target, start_time))

    if path:
        try:
            save_json(build_report(scanner, start_time, end_time), path)
        except OSError as exc:
            print(f"{Colors.RED}[!] Could not save JSON: {exc}{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}[+] Results saved to {os.path.abspath(path)}{Colors.RESET}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AXIOM SECURITY SCANNER v2.0
Author: Plansmight (Kadir Veysel Sayar)
Description: Mathematical Precision Security Scanner with Enhanced UI.

Use only against systems you own or are explicitly authorized to test.
"""

import argparse
import os
import socket
import ssl
import sys
import threading
from datetime import datetime
from queue import Queue

VERSION = "2.0"
DEFAULT_TARGET = "scanme.nmap.org"
DEFAULT_PORTS = "1-1000"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 0.5

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
        "--no-probe",
        action="store_true",
        help="passive mode: never send HTTP requests, only read banners services announce",
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
    def __init__(self, target, ip, ports, threads, timeout, probe=True):
        self.target = target
        self.ip = ip
        self.ports = ports
        self.total = len(ports)
        self.threads = min(threads, self.total)
        self.timeout = timeout
        self.probe = probe
        self.queue = Queue()
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.scanned = 0
        self.results = []  # (port, service, banner)

    def identify(self, sock, port):
        if self.probe:
            if port in HTTPS_PORTS:
                return http_probe(sock, self.target, use_tls=True)
            if port in HTTP_PORTS:
                return http_probe(sock, self.target, use_tls=False)
        return grab_banner(sock)

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.ip, port)) == 0:
                    banner = self.identify(sock, port)
                    service = service_name(port)
                    with self.lock:
                        self.results.append((port, service, banner))
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        print(
                            f"{Colors.GREEN} [+] {port:<6} | {Colors.BOLD}OPEN"
                            f"{Colors.RESET}{Colors.GREEN} | {service:<12} | {banner}{Colors.RESET}"
                        )
        except OSError:
            pass  # unreachable / reset: treat as closed
        finally:
            with self.lock:
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


def print_header(start_time, probe):
    mode = "active (HTTP/HTTPS probe)" if probe else "passive (banner read only)"
    print(f"\n{Colors.GREY}Computation Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.GREY}Mode: {mode}{Colors.RESET}")
    print("-" * 65)
    print(f"{Colors.BOLD} PORT   | STATUS | SERVICE      | BANNER{Colors.RESET}")
    print("-" * 65)


def print_summary(results, duration):
    sys.stdout.write("\r" + " " * 80 + "\r")
    print("-" * 65)
    print(f"{Colors.CYAN}AXIOM ANALYSIS COMPLETE{Colors.RESET}")
    if results:
        print(f"{Colors.BOLD}Open ports (sorted):{Colors.RESET}")
        for port, service, banner in sorted(results):
            print(f"  {Colors.GREEN}{port:<6}{Colors.RESET} {service:<12} {banner}")
        print(f"{Colors.GREY}Banners and Server headers are reported by the remote host, not verified.{Colors.RESET}")
    print(f"Total Open Ports : {Colors.GREEN}{len(results)}{Colors.RESET}")
    print(f"Time Elapsed     : {duration}")
    print("-" * 65 + "\n")


def main():
    args = parse_args()
    print_banner()

    target = args.target or prompt_target()
    ip = resolve_target(target)

    probe = not args.no_probe
    scanner = Scanner(target, ip, args.ports, args.threads, args.timeout, probe)

    start_time = datetime.now()
    print_header(start_time, probe)

    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.done.set()
        print(f"\n\n{Colors.RED}[!] Process Interrupted.{Colors.RESET}")
        sys.exit(130)

    print_summary(scanner.results, datetime.now() - start_time)


if __name__ == "__main__":
    main()

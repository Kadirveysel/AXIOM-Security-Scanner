# 🛡️ AXIOM Security Scanner

> **Mathematical Precision Network Analysis Tool**

AXIOM is a multi-threaded TCP port scanner written in Python, designed for learning, security professionals and system administrators. It features a custom "Kali Linux" style interface, service identification, and visual progress reporting.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

## 🚀 Features

* **Multi-Threaded Architecture:** Scans ports concurrently with a configurable thread count.
* **Flexible Port Selection:** Scan a range (`1-1000`), a list (`22,80,443`), or a mix (`1-100,443`).
* **HTTP/HTTPS Probing:** On common web ports (80, 8000, 8008, 8080, 8081, 8888 and 443, 8443) AXIOM sends a minimal `HEAD /` request and reports the status line and `Server` header. On TLS ports it also reports the negotiated TLS version.
* **Passive Banner Grabbing:** Reads the banner of services that announce themselves on connect (SSH, FTP, SMTP, ...).
* **Safe Output:** Everything a remote host sends back is sanitized before printing, so a hostile banner cannot inject terminal escape sequences.
* **Service Names:** Maps open ports to their standard service name (a hint based on the port number, not a detection).
* **Precision UI:** Visual progress bar and color-coded output.
* **Port States:** Tells apart `open`, `closed` (actively refused) and `filtered` (no answer, usually a firewall) instead of lumping everything that is not open together.
* **Retries:** Ports that time out are retried (`--retries`, default 1) so slow hosts do not hide open ports. Refused connections are final and never retried.
* **Sorted Report:** Open ports listed in port order with scan duration and a count per port state.
* **JSON Export:** After a scan AXIOM asks whether to save the results as JSON, or use `--json FILE` to save without asking.
* **Interactive or CLI Mode:** Pass the target as an argument, or run without one for the interactive prompt.

## 📸 Screenshots

<img width="680" alt="AXIOM Interface" src="https://github.com/user-attachments/assets/0748a650-72b5-44fa-bf8f-6d50bbf05aeb" />

## 🛠️ Installation & Usage

```bash
git clone https://github.com/Kadirveysel/AXIOM-Security-Scanner.git
cd AXIOM-Security-Scanner
python scanner.py
```

Run without arguments for the interactive prompt (press ENTER to scan the default test server), or use the command line:

```bash
python scanner.py scanme.nmap.org                  # default ports 1-1000
python scanner.py 192.168.1.10 -p 1-65535          # full port range
python scanner.py example.local -p 22,80,443       # specific ports
python scanner.py 10.0.0.5 -t 200 --timeout 1.0    # 200 threads, 1s timeout
python scanner.py 10.0.0.5 --no-probe              # passive mode, no HTTP requests
python scanner.py 10.0.0.5 --retries 0             # fastest: no retry on timeouts
python scanner.py 10.0.0.5 --json report.json      # save JSON without asking
```

| Option | Description | Default |
|---|---|---|
| `target` | IP or hostname | interactive prompt |
| `-p`, `--ports` | Port range or list | `1-1000` |
| `-t`, `--threads` | Worker threads | `100` |
| `--timeout` | Connection timeout (seconds) | `0.5` (`3.0` on Windows) |
| `--retries` | Extra attempts for ports that time out | `1` |
| `--no-probe` | Passive mode: never send HTTP requests | off |
| `--json FILE` | Save results to FILE as JSON without asking | ask after the scan |

### About port states and Windows

`filtered` means "no answer within the timeout", which usually points to a firewall dropping packets. Windows reports a refused connection (a closed port) only after its own connection retries, which was measured at about 2 seconds even on `127.0.0.1`. For that reason the default timeout is `3.0` seconds on Windows and `0.5` elsewhere. If you pass a lower `--timeout` on Windows, AXIOM honours it but warns that closed ports may then be reported as `filtered`.

### About the JSON report

When a person is at the keyboard, AXIOM asks `Save results as JSON? [y/N]` after the scan (default: no) and proposes a file name like `axiom_<target>_<date>_<time>.json`. If the file already exists, a numbered name is used so nothing is overwritten. When the input is piped or the tool runs from a script, it never prompts; use `--json FILE` there.

The report contains the target, IP, mode, timings, a port state summary and the open ports with their service and banner. Reports hold details about the scanned host, so `axiom_*.json` is in `.gitignore`.

### About the probe

By default AXIOM is **active**: on web ports it sends a real HTTP request, which appears in the target's logs. Use `--no-probe` if you only want to connect and read announced banners.

The `Server` header and all banners are **reported by the remote host and not verified**; they can be hidden or spoofed. For HTTPS probes, certificate verification is intentionally disabled so that self-signed hosts can be scanned; AXIOM only reads response headers.

## 🗺️ Roadmap

- [x] HTTP/HTTPS probing for web server and TLS version detection
- [x] open / closed / filtered port states with retries
- [x] JSON report export
- [ ] CSV export, CIDR ranges and IPv6
- [ ] Vulnerability hints for detected service versions
- [ ] Unit tests and CI

## ⚠️ Disclaimer

This tool is created for educational purposes and authorized security testing only. The author (Plansmight) is not responsible for any misuse or damage caused by this program. Always obtain permission before scanning a network.

Authored by Plansmight

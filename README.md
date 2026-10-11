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
* **Sorted Report:** Open ports listed in port order with scan duration.
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
```

| Option | Description | Default |
|---|---|---|
| `target` | IP or hostname | interactive prompt |
| `-p`, `--ports` | Port range or list | `1-1000` |
| `-t`, `--threads` | Worker threads | `100` |
| `--timeout` | Connection timeout (seconds) | `0.5` |
| `--no-probe` | Passive mode: never send HTTP requests | off |

### About the probe

By default AXIOM is **active**: on web ports it sends a real HTTP request, which appears in the target's logs. Use `--no-probe` if you only want to connect and read announced banners.

The `Server` header and all banners are **reported by the remote host and not verified**; they can be hidden or spoofed. For HTTPS probes, certificate verification is intentionally disabled so that self-signed hosts can be scanned; AXIOM only reads response headers.

## 🗺️ Roadmap

- [x] HTTP/HTTPS probing for web server and TLS version detection
- [ ] JSON / CSV report export
- [ ] Vulnerability hints for detected service versions
- [ ] Unit tests and CI

## ⚠️ Disclaimer

This tool is created for educational purposes and authorized security testing only. The author (Plansmight) is not responsible for any misuse or damage caused by this program. Always obtain permission before scanning a network.

Authored by Plansmight

# wtmp_reader

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Category](https://img.shields.io/badge/Category-DFIR-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)

A lightweight Python tool for parsing binary `wtmp`/`btmp` log files. Built for environments where `last` or `utmpdump` is unavailable.

Useful for **Digital Forensics & Incident Response (DFIR)**, **Blue Team** investigations, and **SOC** log analysis.

---

## Why?

On minimal or hardened Linux systems (e.g. AWS EC2, Docker containers, CTF environments), tools like `last` and `utmpdump` are often not installed. `wtmp` is a binary file so you can't just `cat` it.

`wtmp-reader` solves that with zero dependencies, just Python 3.

---

## Features

- Full field parsing: `type`, `pid`, `line`, `id`, `user`, `host`, `term`, `exit`, `session`, `timestamp`, `usec`, `addr`
- Color-coded terminal output
- Custom timezone support (`-tz`)
- Export to `.csv` or `.txt` (`-o`)
- Filter by record type (`-f`)
- Summary statistics (`--summary`)
- Works on `wtmp` and `btmp`
- No external dependencies pure Python 3 standard library

---

## Requirements

```
Python 3.x
No external dependencies
```

---

## Usage

```bash
# Basic usage (reads /var/log/wtmp by default)
python3 wtmp_reader.py

# Read a specific file
python3 wtmp_reader.py /path/to/wtmp

# Custom timezone (e.g. WIB = UTC+7)
python3 wtmp_reader.py -tz 7 wtmp

# Export to CSV
python3 wtmp_reader.py -tz 7 wtmp -o output.csv

# Export to TXT
python3 wtmp_reader.py -tz 7 wtmp -o output.txt

# Filter by record type
python3 wtmp_reader.py -f USER wtmp
python3 wtmp_reader.py -f DEAD wtmp
python3 wtmp_reader.py -f BOOT_TIME wtmp

# Show summary statistics
python3 wtmp_reader.py --summary wtmp

# Show all record types including EMPTY
python3 wtmp_reader.py -a wtmp

# Disable color output (useful for piping)
python3 wtmp_reader.py --no-color wtmp

# Combine flags
python3 wtmp_reader.py -tz 7 --summary -f USER -o result.csv wtmp

# Parse failed login attempts (btmp)
sudo python3 wtmp_reader.py /var/log/btmp -tz 7
```

---

## Options

| Flag | Description |
|------|-------------|
| `file` | Path to wtmp/btmp file (default: `/var/log/wtmp`) |
| `-tz`, `--timezone` | UTC offset in hours (e.g. `-tz 7` for WIB, `-tz -5` for EST) |
| `-o`, `--output` | Export output to `.csv` or `.txt` |
| `-f`, `--filter` | Filter by record type (USER, DEAD, BOOT_TIME, LOGIN, INIT, RUN_LVL) |
| `-a`, `--all` | Show all record types including EMPTY |
| `--summary` | Display summary: unique users, IPs, boot count, etc. |
| `--no-color` | Disable colored output (auto-disabled when piping) |

---

## Record Types

| Type | Description |
|------|-------------|
| `BOOT_TIME` | System boot event |
| `USER` | User login session |
| `DEAD` | Session ended |
| `LOGIN` | Login process initialized |
| `INIT` | Init process |
| `RUN_LVL` | Runlevel change (shutdown/reboot) |
| `EMPTY` | Empty record |

---

## CSV Output Format

When exporting with `-o output.csv`, columns are:

```
type, pid, line, id, user, host, term, exit, session, sec, usec, addr
```

---

## Installation

No installation needed. Just clone and run:

```bash
git clone https://github.com/andry968/wtmp_reader.git
cd wtmp_reader
python3 wtmp_reader.py --help
```

---

## Use Cases

- **DFIR investigations** — reconstruct login history from binary logs
- **CTF challenges** — parse wtmp artifacts without relying on system tools
- **SOC analysis** — identify suspicious IPs, unusual login times, or privilege escalation patterns
- **Threat hunting** — correlate login sessions with other log sources

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## References

- [Linux utmp(5) man page](http://man7.org/linux/man-pages/man5/utmp.5.html)
- [/usr/include/bits/utmp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/utsname.h)

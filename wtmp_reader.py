#!/usr/bin/env python3
"""
wtmp_reader.py - Binary wtmp/btmp log parser (full fields)
Usage: python3 wtmp_reader.py [options] [file]
"""

import struct
import ipaddress
import os
import sys
import argparse
import csv
from datetime import datetime, timezone, timedelta

RECORD_SIZE = 384  # fixed utmp record size

# ut_type values
UT_TYPES = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT",
    6: "LOGIN",
    7: "USER",
    8: "DEAD",
    9: "ACCOUNTING",
}

# ANSI colors
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

def parse_wtmp(filepath: str):
    records = []
    try:
        filesize = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            offset = 0
            while offset < filesize:
                f.seek(offset)

                ut_type    = struct.unpack("<L", f.read(4))[0]
                ut_pid     = struct.unpack("<L", f.read(4))[0]
                ut_line    = f.read(32).decode("utf-8", "replace").split('\0', 1)[0]
                ut_id      = f.read(4).decode("utf-8", "replace").split('\0', 1)[0]
                ut_user    = f.read(32).decode("utf-8", "replace").split('\0', 1)[0]
                ut_host    = f.read(256).decode("utf-8", "replace").split('\0', 1)[0]
                ut_term    = struct.unpack("<H", f.read(2))[0]
                ut_exit    = struct.unpack("<H", f.read(2))[0]
                ut_session = struct.unpack("<L", f.read(4))[0]
                tv_sec     = struct.unpack("<L", f.read(4))[0]
                tv_usec    = struct.unpack("<L", f.read(4))[0]
                ip_addr    = str(ipaddress.IPv4Address(struct.unpack(">L", f.read(4))[0]))

                records.append({
                    "type"     : ut_type,
                    "type_str" : UT_TYPES.get(ut_type, f"UNKNOWN({ut_type})"),
                    "pid"      : ut_pid,
                    "line"     : ut_line,
                    "id"       : ut_id,
                    "user"     : ut_user,
                    "host"     : ut_host,
                    "term"     : ut_term,
                    "exit"     : ut_exit,
                    "session"  : ut_session,
                    "tv_sec"   : tv_sec,
                    "tv_usec"  : tv_usec,
                    "addr"     : ip_addr,
                })
                offset += RECORD_SIZE

    except PermissionError:
        print(f"{C.RED}[ERROR]{C.RESET} Permission denied: {filepath}")
        print(f"       Try: {C.YELLOW}sudo python3 wtmp_reader.py{C.RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{C.RED}[ERROR]{C.RESET} File not found: {filepath}")
        sys.exit(1)
    return records

def format_time(tv_sec: int, tv_usec: int, tz_offset: int) -> str:
    if tv_sec == 0:
        return "-"
    tz = timezone(timedelta(hours=tz_offset))
    dt = datetime.fromtimestamp(tv_sec, tz=tz)
    return dt.strftime("%Y/%m/%d %H:%M:%S")

def type_color(ut_type: int) -> str:
    return {
        7: C.GREEN,
        8: C.RED,
        2: C.CYAN,
        6: C.BLUE,
        1: C.YELLOW,
        5: C.MAGENTA,
    }.get(ut_type, C.GRAY)

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════╗
║           wtmp_reader  |  binary log parser          ║
║         for forensics & incident response            ║
╚══════════════════════════════════════════════════════╝{C.RESET}""")

def print_records(records, tz_offset: int, filter_type: str = None, show_all: bool = False):
    w = {
        "type": 10, "pid": 8, "line": 8, "id": 6,
        "user": 14, "host": 18, "term": 5, "exit": 5,
        "session": 8, "sec": 20, "usec": 10, "addr": 16,
    }

    header = (
        f"{C.BOLD}{C.WHITE}"
        f"{'TYPE':<{w['type']}} {'PID':<{w['pid']}} {'LINE':<{w['line']}} "
        f"{'ID':<{w['id']}} {'USER':<{w['user']}} {'HOST':<{w['host']}} "
        f"{'TERM':<{w['term']}} {'EXIT':<{w['exit']}} {'SESS':<{w['session']}} "
        f"{'TIMESTAMP':<{w['sec']}} {'USEC':<{w['usec']}} {'ADDR':<{w['addr']}}"
        f"{C.RESET}"
    )
    total_w = sum(w.values()) + len(w)
    sep = C.GRAY + "─" * total_w + C.RESET

    print(header)
    print(sep)

    count = 0
    for r in records:
        if not show_all and r["type"] == 0:
            continue
        if filter_type and r["type_str"].upper() != filter_type.upper():
            continue

        tc   = type_color(r["type"])
        time = format_time(r["tv_sec"], r["tv_usec"], tz_offset)

        print(
            f"{tc}{r['type_str']:<{w['type']}}{C.RESET} "
            f"{C.GRAY}{r['pid']:<{w['pid']}}{C.RESET} "
            f"{r['line']:<{w['line']}} "
            f"{C.DIM}{r['id']:<{w['id']}}{C.RESET} "
            f"{C.YELLOW}{r['user']:<{w['user']}}{C.RESET} "
            f"{C.MAGENTA}{r['host']:<{w['host']}}{C.RESET} "
            f"{r['term']:<{w['term']}} "
            f"{r['exit']:<{w['exit']}} "
            f"{r['session']:<{w['session']}} "
            f"{C.CYAN}{time:<{w['sec']}}{C.RESET} "
            f"{C.DIM}{r['tv_usec']:<{w['usec']}}{C.RESET} "
            f"{C.GREEN}{r['addr']:<{w['addr']}}{C.RESET}"
        )
        count += 1

    print(sep)
    print(f"{C.BOLD}Total records shown: {C.GREEN}{count}{C.RESET}")

def export_csv(records, filepath: str, tz_offset: int):
    fieldnames = [
        "type", "pid", "line", "id", "user", "host",
        "term", "exit", "session", "sec", "usec", "addr"
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({
                "type"    : r["type_str"],
                "pid"     : r["pid"],
                "line"    : r["line"],
                "id"      : r["id"],
                "user"    : r["user"],
                "host"    : r["host"],
                "term"    : r["term"],
                "exit"    : r["exit"],
                "session" : r["session"],
                "sec"     : format_time(r["tv_sec"], r["tv_usec"], tz_offset),
                "usec"    : r["tv_usec"],
                "addr"    : r["addr"],
            })
    print(f"{C.GREEN}[+]{C.RESET} Saved: {C.BOLD}{filepath}{C.RESET}")

def export_txt(records, filepath: str, tz_offset: int):
    with open(filepath, "w") as f:
        f.write("wtmp_reader output\n" + "=" * 80 + "\n")
        for r in records:
            f.write(
                f"[{r['type_str']}] pid={r['pid']} line={r['line']} id={r['id']} "
                f"user={r['user'] or '-'} host={r['host'] or '-'} "
                f"term={r['term']} exit={r['exit']} session={r['session']} "
                f"time={format_time(r['tv_sec'], r['tv_usec'], tz_offset)} "
                f"usec={r['tv_usec']} addr={r['addr']}\n"
            )
    print(f"{C.GREEN}[+]{C.RESET} Saved: {C.BOLD}{filepath}{C.RESET}")

def print_summary(records, tz_offset: int):
    users  = set(r["user"] for r in records if r["user"])
    hosts  = set(r["host"] for r in records if r["host"])
    addrs  = set(r["addr"] for r in records if r["addr"] not in ("0.0.0.0", ""))
    boots  = sum(1 for r in records if r["type"] == 2)
    logins = sum(1 for r in records if r["type"] == 7)
    dead   = sum(1 for r in records if r["type"] == 8)

    print(f"{C.BOLD}=== SUMMARY ==={C.RESET}")
    print(f"  Total records : {len(records)}")
    print(f"  User logins   : {C.GREEN}{logins}{C.RESET}")
    print(f"  Dead sessions : {C.RED}{dead}{C.RESET}")
    print(f"  Boot events   : {C.CYAN}{boots}{C.RESET}")
    print(f"  Unique users  : {C.YELLOW}{len(users)}{C.RESET} → {', '.join(sorted(users)) or '-'}")
    print(f"  Unique hosts  : {C.MAGENTA}{len(hosts)}{C.RESET} → {', '.join(sorted(hosts)) or '-'}")
    print(f"  Unique IPs    : {C.GREEN}{len(addrs)}{C.RESET} → {', '.join(sorted(addrs)) or '-'}")
    print()

def main():
    parser = argparse.ArgumentParser(
        prog="wtmp_reader",
        description="Binary wtmp/btmp log parser — full fields, for forensics & IR",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "file", nargs="?", default="/var/log/wtmp",
        help="Path to wtmp/btmp file (default: /var/log/wtmp)",
    )
    parser.add_argument(
        "-tz", "--timezone", type=int, default=0, metavar="OFFSET",
        help="UTC offset in hours (e.g. -tz 7 for WIB, -tz -5 for EST)",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Export to file — .csv or .txt",
    )
    parser.add_argument(
        "-f", "--filter", metavar="TYPE",
        help="Filter by type: USER, DEAD, BOOT_TIME, LOGIN, INIT, RUN_LVL",
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="Show all record, include EMPTY",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output (auto juga kalau output di-pipe)",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Show summary: unique users, IPs, boot count, dll",
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        for attr in [a for a in dir(C) if not a.startswith("_")]:
            setattr(C, attr, "")

    print_banner()
    print(f"\n{C.DIM}File : {args.file}")
    print(f"TZ   : UTC{'+' if args.timezone >= 0 else ''}{args.timezone}{C.RESET}\n")

    records = parse_wtmp(args.file)

    if not records:
        print(f"{C.YELLOW}[!]{C.RESET} No records found.")
        sys.exit(0)

    if args.summary:
        print_summary(records, args.timezone)

    print_records(records, args.timezone, filter_type=args.filter, show_all=args.all)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            export_csv(records, args.output, args.timezone)
        else:
            export_txt(records, args.output, args.timezone)

if __name__ == "__main__":
    main()

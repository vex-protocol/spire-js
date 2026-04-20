#!/usr/bin/env python3
"""
Poll Spire's HTTP snapshots and (optionally) the stress harness SQLite trace.

Uses only the stdlib. Intended as a separate "spy" process from Node stress/Spire.

Environment (same as stress):
  SPIRE_STRESS_HOST     default 127.0.0.1:8080
  DEV_API_KEY           required for /status/process
  SPIRE_STRESS_TRACE_DB optional — tail harness_events counts / last row

CLI:
  python3 scripts/stress/spire-spy.py [--interval 1.5] [--pid PID]

--pid: show ps(1) rss/cpu/state for the Spire (or any) process each tick.
       On macOS, "state" is a coarse hint (e.g. sleeping); use `sample` / Instruments
       for stacks, and `sudo fs_usage` for file I/O attribution.

Deeper I/O (not in Python here):
  macOS: sudo fs_usage -w -f filesys | grep -i spire
         sample <pid> 10 -file /tmp/spire.txt
         NODE_OPTIONS='--inspect' on Spire → chrome://inspect
  Linux:  strace -p PID -c   or   bpftrace/eBPF block I/O probes
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def http_json(url: str, headers: dict[str, str], timeout: float) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.getcode() or 0
            if not body:
                return status, None
            return status, json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            return e.code, raw.decode("utf-8", errors="replace")


def fmt_mb(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MiB"


def trace_sqlite_snapshot(path: str) -> str:
    if not path or not os.path.isfile(path):
        return "trace: (no file)"
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM harness_events")
        n = cur.fetchone()[0]
        cur.execute(
            "SELECT seq, event, phase, burst, client_index, detail_json "
            "FROM harness_events ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        con.close()
        if row is None:
            return f"trace: events={n}"
        seq, ev, ph, bu, ci, dj = row
        tail = (dj or "")[: 80]
        return f"trace: events={n}  last seq={seq} {ph}/{ev} burst={bu} ci={ci} {tail!r}"
    except sqlite3.Error as e:
        return f"trace: sqlite error {e}"


def ps_snapshot(pid: int) -> str:
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "etime=,rss=,vsz=,%cpu=,state="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        line = (out.stdout or "").strip().replace("\n", " ")
        if out.returncode != 0 or not line:
            return f"ps {pid}: (missing or exited)"
        return f"pid {pid}: {line}"
    except (OSError, subprocess.SubprocessError) as e:
        return f"ps {pid}: {e}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll Spire + optional stress SQLite trace")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.5,
        help="Seconds between polls (default 1.5)",
    )
    parser.add_argument(
        "--pid",
        type=int,
        default=0,
        help="Optional Spire (or other) PID for ps(1) rss/cpu/state",
    )
    args = parser.parse_args()

    host = os.environ.get("SPIRE_STRESS_HOST", "127.0.0.1:8080").strip()
    key = (os.environ.get("DEV_API_KEY") or "").strip()
    trace_db = (os.environ.get("SPIRE_STRESS_TRACE_DB") or "").strip()
    if not trace_db:
        default_trace = os.path.expanduser("~/.spire-stress/traces.sqlite")
        if os.path.isfile(default_trace):
            trace_db = default_trace

    if not key:
        print("DEV_API_KEY is required (same as Spire + stress).", file=sys.stderr)
        return 1

    if host.startswith("http://") or host.startswith("https://"):
        base = host.rstrip("/")
    else:
        base = "http://" + host

    hdr = {"x-dev-api-key": key, "Accept": "application/json"}
    st_url = f"{base}/status"
    pr_url = f"{base}/status/process"

    print(
        "spire-spy  Ctrl+C to stop\n"
        f"  Spire     {base}\n"
        f"  interval  {args.interval}s\n"
        f"  trace DB  {trace_db or '(env SPIRE_STRESS_TRACE_DB unset)'}\n"
        f"  pid       {args.pid or '(none)'}\n",
        flush=True,
    )

    while True:
        ts = time.strftime("%H:%M:%S")
        st_s, st_j = http_json(st_url, hdr, timeout=3.0)
        pr_s, pr_j = http_json(pr_url, hdr, timeout=3.0)

        line1 = f"[{ts}] GET /status → {st_s}"
        if isinstance(st_j, dict):
            db = st_j.get("dbHealthy")
            chk = st_j.get("checkDurationMs")
            line1 += f"  db={db}  chk={chk}ms"

        line2 = f"         GET /status/process → {pr_s}"
        if pr_s == 200 and isinstance(pr_j, dict):
            mem = pr_j.get("memory")
            rss = mem.get("rss") if isinstance(mem, dict) else None
            ws = pr_j.get("websocketClients")
            up = pr_j.get("uptimeSeconds")
            ru = pr_j.get("resourceUsage") or {}
            fr = ru.get("fsRead")
            fw = ru.get("fsWrite")
            rss_s = fmt_mb(int(rss)) if isinstance(rss, int) else "?"
            line2 += f"  rss={rss_s}  ws={ws}  up={up}s  fs_rd={fr} fs_wr={fw}"
        elif pr_s == 404:
            line2 += "  (404: set DEV_API_KEY on Spire for snapshot)"

        print(line1, flush=True)
        print(line2, flush=True)

        if trace_db:
            print(f"         {trace_sqlite_snapshot(trace_db)}", flush=True)
        if args.pid > 0:
            print(f"         {ps_snapshot(args.pid)}", flush=True)

        print(flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nbye.", file=sys.stderr)
        raise SystemExit(0)

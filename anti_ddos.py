#python3 anti_ddos.py --log-file /tmp/test.log

import argparse
import re
import time
from collections import defaultdict, deque
from pathlib import Path

WINDOW_SECONDS = 60
ALERT_THRESHOLD = 4  # Report once an IP tries more than 3 ports (or >= 4) in the window
EXEMPT_PORTS = {80, 443}

SRC_RE = re.compile(r"\bSRC=([0-9a-fA-F:.]+)\b")
DPT_RE = re.compile(r"\bDPT=(\d+)\b")


def record_attempt(
    ip_str: str,
    port: int,
    attempts: dict[str, deque[tuple[float, int]]],
    window_seconds: int = WINDOW_SECONDS,
    exempt_ports: set[int] = EXEMPT_PORTS,
    now: float | None = None,
) -> list[int] | None:
    """Record a port probe for ip_str and prune entries older than window_seconds.

    Returns the sorted list of unique ports tried in the window if unique port
    count exceeds (ALERT_THRESHOLD - 1), otherwise None.
    """
    if port in exempt_ports:
        return None

    ts = time.monotonic() if now is None else now
    q = attempts[ip_str]

    while q and ts - q[0][0] > window_seconds:
        q.popleft()

    q.append((ts, port))

    unique_ports = sorted({p for _, p in q})
    if len(unique_ports) > (ALERT_THRESHOLD - 1):
        return unique_ports
    return None


def format_history(q: deque[tuple[float, int]], now: float) -> str:
    """Format recent (timestamp, port) attempts relative to now."""
    parts = [f"{port} (-{now - ts:.1f}s)" for ts, port in q]
    return ", ".join(parts)


def process_line(
    line: str,
    attempts: dict[str, deque[tuple[float, int]]],
    window_seconds: int = WINDOW_SECONDS,
) -> None:
    src_match = SRC_RE.search(line)
    dpt_match = DPT_RE.search(line)
    if not src_match or not dpt_match:
        return

    ip_str = src_match.group(1)
    port = int(dpt_match.group(1))
    now = time.monotonic()

    unique_ports = record_attempt(
        ip_str=ip_str,
        port=port,
        attempts=attempts,
        window_seconds=window_seconds,
        now=now,
    )
    if unique_ports is not None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        history = format_history(attempts[ip_str], now)
        print(
            f"[{stamp}] ip={ip_str} window={window_seconds}s "
            f"unique_ports={unique_ports} attempts=[{history}]",
            flush=True,
        )


def tail_file(path: Path, from_start: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8") as f:
        if not from_start:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Show all ports an IP tried over a time window.")
    parser.add_argument("--log-file", required=True, help="Path to log file containing SRC=... DPT=...")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS, help="Time window in seconds.")
    parser.add_argument("--from-start", action="store_true", help="Read existing file lines first.")
    args = parser.parse_args()

    attempts: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
    print(f"Tracking ports per IP over a {args.window}s window from {args.log_file}...", flush=True)

    for line in tail_file(Path(args.log_file), from_start=args.from_start):
        process_line(line, attempts, window_seconds=args.window)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
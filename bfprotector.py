#python3 bfprotector.py --log-file /tmp/auth_test.log --max-failures 3

import argparse
import ipaddress
import re
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path

NFT_BIN = "/usr/sbin/nft"
MAX_FAILURES = 5          # Block after 5 failed attempts (on the 6th)
WINDOW_SECONDS = 60
BAN_SECONDS = 3600
ALERT_LOG = "/tmp/brute_bans.log"
BAN_LIST_FILE = "/tmp/banned_ips.txt"

TRUSTED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# Matches common SSH / auth / web failure log formats:
# - "Failed password for invalid user admin from 198.51.100.23 port 44122 ssh2"
# - "AUTH_FAIL: SRC=198.51.100.23 user=root"
# - "401 login failed ip=198.51.100.23"
FAIL_PATTERNS = [
    re.compile(r"\bFailed password for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+)\b"),
    re.compile(r"\bAUTH_FAIL:.*\b(?:SRC|IP|ip)=([0-9a-fA-F:.]+)\b"),
    re.compile(r"\b(?:login failed|invalid credentials|authentication failure)\b.*?\b(?:from|ip=|SRC=)([0-9a-fA-F:.]+)\b", re.IGNORECASE),
]


def is_trusted_or_invalid_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if addr.version != 4:
        return True
    return any(addr in net for net in TRUSTED_NETS)


def extract_failed_ip(line: str) -> str | None:
    for pattern in FAIL_PATTERNS:
        m = pattern.search(line)
        if m:
            ip_str = m.group(1)
            if not is_trusted_or_invalid_ip(ip_str):
                return ip_str
    return None


def sync_ban_list_file(active_bans: dict[str, float], now: float) -> None:
    """Write currently non-expired banned IPs to BAN_LIST_FILE for app/proxy enforcement."""
    expired = [ip for ip, exp in active_bans.items() if exp <= now]
    for ip in expired:
        del active_bans[ip]

    Path(BAN_LIST_FILE).write_text(
        "\n".join(sorted(active_bans.keys())) + ("\n" if active_bans else ""),
        encoding="utf-8",
    )


def try_nft_ban(ip_str: str, ban_seconds: int) -> bool:
    """Add IP to nftables blacklist set if permitted; return True on success."""
    try:
        subprocess.run(
            [
                NFT_BIN,
                "add",
                "element",
                "inet",
                "scan_guard",
                "blacklist",
                f"{{ {ip_str} timeout {ban_seconds}s }}",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def enforce_ban(ip_str: str, active_bans: dict[str, float], now: float, ban_seconds: int = BAN_SECONDS) -> None:
    active_bans[ip_str] = now + ban_seconds
    sync_ban_list_file(active_bans, now)

    nft_ok = try_nft_ban(ip_str, ban_seconds)
    mode = "nftables+banlist" if nft_ok else "banlist-only (nftables restricted)"
    msg = f"{time.strftime('%Y-%m-%d %H:%M:%S')} BAN ip={ip_str} duration={ban_seconds}s mode={mode}\n"

    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(msg)
    print(msg.strip(), flush=True)


def process_line(
    line: str,
    failures: dict[str, deque[float]],
    active_bans: dict[str, float],
    max_failures: int = MAX_FAILURES,
    window_seconds: int = WINDOW_SECONDS,
    ban_seconds: int = BAN_SECONDS,
) -> bool:
    ip_str = extract_failed_ip(line)
    if not ip_str:
        return False

    now = time.monotonic()
    if active_bans.get(ip_str, 0) > now:
        return False

    q = failures[ip_str]
    while q and now - q[0] > window_seconds:
        q.popleft()

    q.append(now)

    if len(q) > max_failures:
        q.clear()
        enforce_ban(ip_str, active_bans, now, ban_seconds=ban_seconds)
        return True

    return False


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


def stream_ssh_journal():
    proc = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0", "-o", "cat"],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            yield line
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect and block brute-force login attempts.")
    parser.add_argument("--log-file", help="Auth/app log file to monitor instead of ssh journalctl.")
    parser.add_argument("--from-start", action="store_true", help="Read existing log lines before tailing.")
    parser.add_argument("--max-failures", type=int, default=MAX_FAILURES, help="Max failures before ban.")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS, help="Sliding window in seconds.")
    parser.add_argument("--ban-seconds", type=int, default=BAN_SECONDS, help="Ban duration in seconds.")
    args = parser.parse_args()

    failures: dict[str, deque[float]] = defaultdict(deque)
    active_bans: dict[str, float] = {}
    source = tail_file(Path(args.log_file), from_start=args.from_start) if args.log_file else stream_ssh_journal()

    print(
        f"Monitoring brute-force attempts (ban after >{args.max_failures} failures in {args.window}s)...",
        flush=True,
    )
    for line in source:
        process_line(
            line,
            failures,
            active_bans,
            max_failures=args.max_failures,
            window_seconds=args.window,
            ban_seconds=args.ban_seconds,
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
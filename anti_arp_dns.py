#python3 anti_arp_dns.py --interval 10 --domains example.com debian.org

import argparse
import ipaddress
import socket
import subprocess
import time
from pathlib import Path

ALERT_LOG = "/tmp/arp_dns_alerts.log"
BAN_LIST_FILE = "/tmp/banned_ips.txt"

PINNED_ARP: dict[str, str] = {}
PINNED_DNS: dict[str, set[str]] = {}


def log_alert(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n"
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(line)
    print(line.strip(), flush=True)


def append_ban_ip(ip_str: str) -> None:
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return
    path = Path(BAN_LIST_FILE)
    existing = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    if ip_str not in existing:
        existing.add(ip_str)
        path.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


def read_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    arp_path = Path("/proc/net/arp")
    if not arp_path.exists():
        return table

    for line in arp_path.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_str, _hw_type, flags, mac = parts[0], parts[1], parts[2], parts[3].lower()
        if flags == "0x0" or mac == "00:00:00:00:00:00":
            continue
        table[ip_str] = mac
    return table


def try_pin_arp(ip_str: str, mac: str, dev: str | None = None) -> bool:
    cmd = ["ip", "neigh", "replace", ip_str, "lladdr", mac]
    if dev:
        cmd.extend(["dev", dev])
    cmd.extend(["nud", "permanent"])
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def check_arp(known_arp: dict[str, str], dev: str | None = None) -> None:
    current = read_arp_table()

    mac_to_ips: dict[str, list[str]] = {}
    for ip_str, mac in current.items():
        mac_to_ips.setdefault(mac, []).append(ip_str)

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            log_alert(f"ARP_MULTI_IP mac={mac} ips={ips}")

    for ip_str, mac in current.items():
        expected_mac = PINNED_ARP.get(ip_str) or known_arp.get(ip_str)
        if expected_mac and expected_mac != mac:
            pinned = try_pin_arp(ip_str, expected_mac, dev=dev)
            status = "repinned" if pinned else "alert-only (permission denied)"
            log_alert(
                f"ARP_SPOOF_SUSPECT ip={ip_str} old_mac={expected_mac} new_mac={mac} action={status}"
            )
            append_ban_ip(ip_str)
        elif ip_str not in known_arp:
            known_arp[ip_str] = mac


def resolve_system_ips(domain: str) -> set[str]:
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(domain, None, family=socket.AF_INET):
            addr = info[4][0]
            if isinstance(addr, str):
                ips.add(addr)
    except socket.gaierror:
        pass
    return ips


def check_dns(domains: list[str]) -> None:
    for domain in domains:
        resolved = resolve_system_ips(domain)
        if not resolved:
            continue

        for ip_str in sorted(resolved):
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                log_alert(f"DNS_PRIVATE_IP domain={domain} resolved_ip={ip_str}")

        pinned = PINNED_DNS.get(domain)
        if pinned and not (resolved & pinned):
            log_alert(
                f"DNS_MISMATCH domain={domain} resolved={sorted(resolved)} expected={sorted(pinned)}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor ARP table and DNS resolutions for spoofing.")
    parser.add_argument("--interval", type=float, default=5.0, help="Check interval in seconds.")
    parser.add_argument("--dev", help="Network interface name for optional ARP repinning (e.g. eth0).")
    parser.add_argument(
        "--domains",
        nargs="*",
        default=["example.com", "cloudflare.com"],
        help="Domains to check for unexpected resolutions.",
    )
    args = parser.parse_args()

    known_arp = read_arp_table()
    print(f"Monitoring ARP ({len(known_arp)} initial entries) and DNS ({args.domains})...", flush=True)

    while True:
        check_arp(known_arp, dev=args.dev)
        check_dns(args.domains)
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
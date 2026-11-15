
import argparse
import csv
import json
import logging
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlparse

from scapy.all import IP, TCP, UDP, Raw, rdpcap, sniff

CUPS_BROWSED_PORT = 631

log = logging.getLogger("cups_detector")


# Allowlist endpoints
def parse_endpoint(spec: str):
    if ":" in spec:
        host, _, port = spec.rpartition(":")
        if port.isdigit() and host:
            return (host, int(port))
    return (spec, None)


# Browse-payload parsing
def parse_browse(payload: bytes):
    problems = []
    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return None, ["empty payload"]

    tokens = text.split(None, 2)  # type, state, remainder(uri + quoted fields)
    if len(tokens) < 3:
        return {"raw": text}, ["too few fields (expected type state uri ...)"]

    type_tok, state_tok, remainder = tokens
    parsed = {"type": type_tok, "state": state_tok, "raw": text}

    if not type_tok.lstrip("0x").isdigit() and not type_tok.isdigit():
        problems.append(f"non-numeric type field: {type_tok!r}")
    if not state_tok.isdigit():
        problems.append(f"non-numeric state field: {state_tok!r}")

    uri = remainder.split(None, 1)[0]
    parsed["uri"] = uri
    try:
        u = urlparse(uri)
        if not u.scheme or not u.hostname:
            problems.append(f"unparseable uri: {uri!r}")
        else:
            parsed["uri_host"] = u.hostname
            parsed["uri_port"] = u.port
            parsed["uri_scheme"] = u.scheme
    except ValueError:
        problems.append(f"invalid uri: {uri!r}")

    return parsed, problems


# Detector
class Detector:
    def __init__(self, allow, watch_ports, flood_threshold, flood_window):
        # allow: list of "IP" / "IP:PORT" strings
        self.allow_endpoints = {parse_endpoint(a) for a in allow}
        self.allow_ips = {ip for ip, _ in self.allow_endpoints}
        self.flood_threshold = flood_threshold
        self.flood_window = flood_window
        self.alerts = []
        self._adv_times = defaultdict(deque)   # src -> timestamps of adverts
        self._last_flood_alert = {}            # src -> last flood alert ts

        # Inspect TCP to: 631, any explicitly watched port, and any port that
        # appears in an allowlist endpoint (so legit printer ports are checked
        # and then cleared, while unknown endpoints on them are flagged).
        self.watch_ports = {CUPS_BROWSED_PORT} | set(watch_ports)
        self.watch_ports |= {p for _, p in self.allow_endpoints if p is not None}

    # -- authorization ------------------------------------------------------ #
    def _authorized(self, ip, port):
        """True if ip:port is an allowed printer endpoint."""
        if (ip, port) in self.allow_endpoints:
            return True
        if (ip, None) in self.allow_endpoints:   # bare IP = any port on host
            return True
        return False

    # -- alert helper ------------------------------------------------------- #
    def alert(self, ts, category, severity, src, dst, detail):
        rec = {
            "timestamp": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
            "category": category,
            "severity": severity,
            "src": src,
            "dst": dst,
            "detail": detail,
        }
        self.alerts.append(rec)
        log.warning("[%s/%s] %s -> %s : %s", severity, category, src, dst, detail)

    # -- per-packet entry point -------------------------------------------- #
    def process(self, pkt):
        if IP not in pkt:
            return
        ts = float(getattr(pkt, "time", time.time()))
        src = pkt[IP].src
        dst = pkt[IP].dst

        if UDP in pkt and (pkt[UDP].dport == CUPS_BROWSED_PORT
                           or pkt[UDP].sport == CUPS_BROWSED_PORT):
            self._inspect_browse(pkt, ts, src, dst)
        elif TCP in pkt and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
            # SYN without ACK = connection attempt
            self._inspect_ipp(pkt, ts, src, dst)

    # -- UDP browse advertisements ----------------------------------------- #
    def _inspect_browse(self, pkt, ts, src, dst):
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
        parsed, problems = parse_browse(payload)

        # 1) malformed fields
        for p in problems:
            self.alert(ts, "malformed_field", "medium", src, dst, p)

        # 2) advertised endpoint not authorized (the key port-aware check)
        if self.allow_endpoints and parsed and parsed.get("uri_host"):
            host = parsed["uri_host"]
            port = parsed.get("uri_port")
            if not self._authorized(host, port):
                self.alert(ts, "unauthorized_advertisement", "high", src, dst,
                           f"advertises printer endpoint {host}:{port} "
                           f"not on allowlist")

        # 3) advertised-host vs packet-source mismatch (abnormal / spoof)
        if parsed and parsed.get("uri_host"):
            host = parsed["uri_host"]
            if host != src and not self._authorized(host, parsed.get("uri_port")):
                self.alert(ts, "address_mismatch", "medium", src, dst,
                           f"advertises callback host {host} "
                           f"(port {parsed.get('uri_port')}) != packet source")

        # 4) flood / repeated discovery
        self._track_flood(ts, src, dst)

    def _track_flood(self, ts, src, dst):
        q = self._adv_times[src]
        q.append(ts)
        while q and ts - q[0] > self.flood_window:
            q.popleft()
        if len(q) >= self.flood_threshold:
            last = self._last_flood_alert.get(src, 0)
            if ts - last >= self.flood_window:  # one flood alert per window
                self._last_flood_alert[src] = ts
                self.alert(ts, "discovery_flood", "high", src, dst,
                           f"{len(q)} advertisements in {self.flood_window}s "
                           f"(threshold {self.flood_threshold})")

    # -- TCP IPP connections ----------------------------------------------- #
    def _inspect_ipp(self, pkt, ts, src, dst):
        dport = pkt[TCP].dport
        if dport not in self.watch_ports:
            return
        if self._authorized(dst, dport):
            return  # connection to an authorized printer endpoint
        self.alert(ts, "suspicious_ipp", "medium", src, dst,
                   f"IPP/TCP connection to unauthorized endpoint {dst}:{dport}")

    # -- export ------------------------------------------------------------ #
    def export(self, path, fmt):
        if not path:
            return
        if fmt == "json":
            with open(path, "w") as f:
                json.dump(self.alerts, f, indent=2)
        else:
            fields = ["timestamp", "category", "severity", "src", "dst", "detail"]
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                w.writerows(self.alerts)
        log.info("Wrote %d alert(s) to %s (%s)", len(self.alerts), path, fmt)


# CLI
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Detect suspicious CUPS discovery / IPP activity (Scapy).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="Interface for live capture (needs root)")
    src.add_argument("--pcap", help="PCAP file for offline analysis")

    p.add_argument("--allow", action="append", default=[], metavar="IP[:PORT]",
                   help="Authorized printer endpoint. 'IP:PORT' allows that exact "
                        "endpoint; bare 'IP' allows any port on that host. Repeatable.")
    p.add_argument("--watch-port", action="append", type=int, default=[],
                   metavar="PORT", help="Extra IPP/callback port to inspect (repeatable)")
    p.add_argument("--flood-threshold", type=int, default=5,
                   help="Advertisements per window that count as a flood")
    p.add_argument("--flood-window", type=float, default=10.0,
                   help="Flood detection window in seconds")
    p.add_argument("--bpf", default=None, help="Override the BPF capture filter")
    p.add_argument("--output", default=None, help="Write alerts to this file")
    p.add_argument("--format", choices=["csv", "json"], default="json",
                   help="Export format")
    p.add_argument("--count", type=int, default=0,
                   help="Live mode: stop after N packets (0 = run until Ctrl-C)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args(argv)


def build_bpf(watch_ports):
    ports = sorted({CUPS_BROWSED_PORT} | set(watch_ports))
    clauses = ["udp port 631"] + [f"tcp port {p}" for p in ports]
    return " or ".join(clauses)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    det = Detector(args.allow, args.watch_port, args.flood_threshold, args.flood_window)
    # BPF covers 631 plus every watched port (explicit + from allow endpoints).
    bpf = args.bpf or build_bpf(det.watch_ports)
    log.info("Capture filter: %s", bpf)
    if det.allow_endpoints:
        pretty = ", ".join(f"{ip}:{port if port is not None else '*'}"
                           for ip, port in sorted(det.allow_endpoints,
                                                   key=lambda e: (e[0], e[1] or 0)))
        log.info("Authorized endpoints: %s", pretty)
        log.info("Watched IPP ports: %s", ", ".join(str(p) for p in sorted(det.watch_ports)))

    if args.pcap:
        log.info("Offline analysis of %s", args.pcap)
        try:
            packets = rdpcap(args.pcap)
        except (FileNotFoundError, OSError) as e:
            log.error("Could not read PCAP: %s", e)
            return 1
        for pkt in packets:
            det.process(pkt)
    else:
        log.info("Live capture on %s (Ctrl-C to stop)", args.iface)
        try:
            sniff(iface=args.iface, filter=bpf, prn=det.process,
                  store=False, count=args.count)
        except PermissionError:
            log.error("Live capture needs root/CAP_NET_RAW - try sudo.")
            return 1
        except KeyboardInterrupt:
            pass

    log.info("Done - %d alert(s) raised", len(det.alerts))
    det.export(args.output, args.format)
    return 0


if __name__ == "__main__":
    sys.exit(main())

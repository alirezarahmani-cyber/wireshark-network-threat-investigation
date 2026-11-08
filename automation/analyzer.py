#!/usr/bin/env python3
"""Offline PCAP/PCAPNG triage helper. Does not execute or export payloads."""

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from urllib.parse import urlsplit

from scapy.all import ARP, IP, IPv6, PcapReader, Raw, TCP, UDP


METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


def load_indicators(path):
    result = {"ips": set(), "domains": set(), "uris": set()}
    if path is None:
        return result
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Indicator JSON must be an object with optional ips, domains, uris arrays")
    for key in result:
        values = data.get(key, [])
        if not isinstance(values, list) or any(not isinstance(x, str) for x in values):
            raise ValueError(f"Indicator '{key}' must be an array of strings")
        result[key] = {v.lower().rstrip(".") if key == "domains" else v for v in values}
    return result


def parse_http_request(payload):
    """Recognize HTTP/1.x request at the start of a single TCP payload."""
    header = payload.split(b"\r\n\r\n", 1)[0][:16384]
    lines = header.split(b"\r\n")
    if not lines:
        return None
    first = lines[0].decode("latin-1", errors="replace").split(" ")
    if len(first) != 3 or first[0] not in METHODS or not first[2].startswith("HTTP/1."):
        return None
    method, uri = first[0], first[1]
    host = ""
    for line in lines[1:]:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
            break
    split = urlsplit(uri)
    path = split.path or "/"
    if not uri.startswith(("http://", "https://")) and uri != "*":
        path = uri.split("?", 1)[0] or "/"
    hostname = split.hostname if split.hostname else host.split(":", 1)[0]
    domain = hostname.lower().rstrip(".") if hostname else ""
    return method, uri, path, host, domain


def write_csv(path, fields, records):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def run(pcap_path, output_dir, indicators):
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    pairs = Counter()
    requests, matches = [], []
    repeated = defaultdict(list)
    first_time = None

    with PcapReader(str(pcap_path)) as reader:
        for frame, packet in enumerate(reader, 1):
            counts["total_packets"] += 1
            stamp = float(packet.time)
            if first_time is None:
                first_time = stamp
            relative = round(stamp - first_time, 6)
            utc = datetime.fromtimestamp(stamp, timezone.utc).isoformat()

            if ARP in packet:
                counts["arp_packets"] += 1
                continue
            if IP in packet:
                ip, version = packet[IP], 4
                counts["ipv4_packets"] += 1
            elif IPv6 in packet:
                ip, version = packet[IPv6], 6
                counts["ipv6_packets"] += 1
            else:
                counts["other_packets"] += 1
                continue

            src, dst = str(ip.src), str(ip.dst)
            if TCP in packet:
                transport = packet[TCP]
                protocol = "TCP"
                counts["tcp_packets"] += 1
                source_port, destination_port = int(transport.sport), int(transport.dport)
            elif UDP in packet:
                transport = packet[UDP]
                protocol = "UDP"
                counts["udp_packets"] += 1
                source_port, destination_port = int(transport.sport), int(transport.dport)
            else:
                protocol = str(int(ip.proto) if version == 4 else int(ip.nh))
                source_port = destination_port = ""

            pairs[(version, src, dst, protocol)] += 1
            common = {
                "frame": frame, "relative_seconds": relative, "timestamp_utc": utc,
                "source_ip": src, "destination_ip": dst,
                "source_port": source_port, "destination_port": destination_port,
            }
            for indicator in sorted({src, dst} & indicators["ips"]):
                matches.append({**common, "indicator_type": "ip", "indicator": indicator,
                                "method": "", "uri": "", "domain": ""})

            if protocol != "TCP" or Raw not in packet:
                continue
            parsed = parse_http_request(bytes(packet[Raw].load))
            if parsed is None:
                continue
            method, uri, path, host, domain = parsed
            requests.append({**common, "method": method, "uri": uri, "path": path,
                             "host": host, "domain": domain})
            counts["http_requests_detected"] += 1
            repeated[(src, dst, method, path)].append(relative)
            for indicator in sorted({uri, path} & indicators["uris"]):
                matches.append({**common, "indicator_type": "uri", "indicator": indicator,
                                "method": method, "uri": uri, "domain": domain})
            if domain and domain in indicators["domains"]:
                matches.append({**common, "indicator_type": "domain", "indicator": domain,
                                "method": method, "uri": uri, "domain": domain})

    pair_rows = [{"ip_version": v, "source_ip": src, "destination_ip": dst,
                  "protocol": proto, "packet_count": count}
                 for (v, src, dst, proto), count in pairs.most_common()]
    activity_rows = []
    for (src, dst, method, path), timestamps in repeated.items():
        if len(timestamps) < 2:
            continue
        gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
        activity_rows.append({
            "source_ip": src, "destination_ip": dst, "method": method, "path": path,
            "request_count": len(timestamps),
            "first_relative_seconds": round(timestamps[0], 6),
            "last_relative_seconds": round(timestamps[-1], 6),
            "median_interval_seconds": round(median(gaps), 3),
        })
    activity_rows.sort(key=lambda item: item["request_count"], reverse=True)

    write_csv(output_dir / "network_pairs.csv",
              ["ip_version", "source_ip", "destination_ip", "protocol", "packet_count"], pair_rows)
    write_csv(output_dir / "http_requests.csv",
              ["frame", "relative_seconds", "timestamp_utc", "source_ip", "destination_ip",
               "source_port", "destination_port", "method", "uri", "path", "host", "domain"], requests)
    write_csv(output_dir / "indicator_matches.csv",
              ["frame", "relative_seconds", "timestamp_utc", "source_ip", "destination_ip",
               "source_port", "destination_port", "indicator_type", "indicator", "method", "uri", "domain"], matches)
    write_csv(output_dir / "repeated_http.csv",
              ["source_ip", "destination_ip", "method", "path", "request_count",
               "first_relative_seconds", "last_relative_seconds", "median_interval_seconds"], activity_rows)

    summary = {
        "input_file": str(pcap_path.resolve()),
        "total_packets": counts["total_packets"],
        "ipv4_packets": counts["ipv4_packets"],
        "ipv6_packets": counts["ipv6_packets"],
        "arp_packets": counts["arp_packets"],
        "other_packets": counts["other_packets"],
        "tcp_packets": counts["tcp_packets"],
        "udp_packets": counts["udp_packets"],
        "directional_ip_protocol_pairs": len(pairs),
        "http_requests_detected": len(requests),
        "indicator_match_records": len(matches),
        "repeated_http_groups": len(activity_rows),
        "limits": [
            "No TCP stream reassembly; segmented HTTP requests may be missed.",
            "Only plaintext HTTP/1.x requests recognizable at start of a TCP payload are parsed.",
            "Encrypted HTTPS contents are not decrypted.",
            "Indicator matches and repeated requests do not prove malicious activity.",
            "HTTP request counts are not equivalent to Wireshark HTTP packet counts.",
        ],
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n=== PCAP TRIAGE SUMMARY ===")
    for key, value in summary.items():
        if key not in ("limits", "input_file"):
            print(f"{key}: {value}")
    print("\nTop 5 communication pairs:")
    for item in pair_rows[:5]:
        print(f"  {item['source_ip']} -> {item['destination_ip']} "
              f"({item['protocol']}): {item['packet_count']}")
    print(f"\nResults saved to: {output_dir.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Reusable offline PCAP/PCAPNG triage (no live traffic)")
    parser.add_argument("pcap", type=Path, help="Path to a .pcap or .pcapng file")
    parser.add_argument("--indicators", type=Path, help="Optional JSON with ips, domains, uris")
    parser.add_argument("--output-dir", type=Path, help="Output folder (default: output/<input-stem>)")
    args = parser.parse_args()
    if not args.pcap.is_file():
        parser.error(f"Capture file not found: {args.pcap}")
    if args.indicators and not args.indicators.is_file():
        parser.error(f"Indicator file not found: {args.indicators}")
    out = args.output_dir or Path("output") / args.pcap.stem
    try:
        run(args.pcap, out, load_indicators(args.indicators))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()

from __future__ import annotations

import hashlib
import os
import struct
from collections import defaultdict
from typing import Any

try:
    from scapy.layers.inet import IP, TCP, UDP
except ImportError:
    IP = TCP = UDP = None

try:
    from scapy.layers.dns import DNS
except ImportError:
    DNS = None

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")

SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".tk",
    ".pw", ".bid", ".men", ".loan", ".download", ".review",
}

EXFIL_THRESHOLD = 1024 * 100        # 100 KB
MIN_BEACON_SAMPLES = 3
BEACON_CV_THRESHOLD = 0.5
RAPID_CONN_MS = 500                # less than 500ms between connections


def analyze_pcap(pcap_path: str | None = None) -> dict[str, Any]:
    if pcap_path is None:
        pcap_path = os.path.join(MONITOR_DIR, "traffic.pcap")

    if not pcap_path or not os.path.isfile(pcap_path):
        return {"error": "pcap file not found", "pcap_path": pcap_path, "findings": []}

    try:
        from scapy.all import rdpcap
    except ImportError:
        return {"error": "scapy not installed", "findings": []}

    if IP is None or TCP is None:
        return {"error": "scapy layers not available", "findings": []}

    packets = rdpcap(pcap_path)

    dns_queries = _extract_dns(packets)
    tls_handshakes = _extract_tls(packets)
    connections = _extract_connections(packets)
    data_volume = _calc_data_volume(packets)
    beaconing = _detect_beaconing(packets)
    non_http = _detect_non_http(packets)
    findings = _generate_findings(
        dns_queries, tls_handshakes, connections,
        data_volume, beaconing, non_http,
    )

    return {
        "dns_queries": dns_queries,
        "tls_handshakes": tls_handshakes,
        "connections": connections,
        "data_volume": data_volume,
        "beaconing": beaconing,
        "non_http_connections": non_http,
        "findings": findings,
        "packet_count": len(packets),
    }


# ── DNS extraction ────────────────────────────────────────────────────────

def _decode_dns_name(name) -> str:
    if isinstance(name, bytes):
        return name.decode(errors="replace")
    return str(name)


def _dns_qtype_str(qtype: int) -> str:
    types = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA",
             33: "SRV", 39: "DNAME", 255: "ANY"}
    return types.get(qtype, str(qtype))


def _extract_dns(packets) -> list[dict]:
    queries: list[dict] = []
    seen: set[tuple[str, float]] = set()

    if DNS is None:
        return queries

    for pkt in packets:
        if not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
            continue
        udp = pkt[UDP]
        if udp.dport != 53 and udp.sport != 53:
            continue

        dns = pkt[DNS]

        if dns.qr == 0 and dns.qd is not None:
            qd_list = dns.qd if isinstance(dns.qd, list) else [dns.qd]
            for q in qd_list:
                if q is None:
                    continue
                domain = _decode_dns_name(q.qname).rstrip(".")
                key = (domain, round(float(pkt.time), 1))
                if key not in seen:
                    seen.add(key)
                    queries.append({
                        "domain": domain,
                        "type": _dns_qtype_str(q.qtype),
                        "timestamp": float(pkt.time),
                        "direction": "query",
                    })

        if dns.qr == 1 and dns.an is not None:
            an_list = dns.an if isinstance(dns.an, list) else [dns.an]
            resolved: list[str] = []
            for rr in an_list:
                if rr is None:
                    continue
                try:
                    if rr.type == 1:
                        resolved.append(str(rr.rdata))
                    elif rr.type in (5, 39):
                        resolved.append(_decode_dns_name(rr.rdata).rstrip("."))
                except AttributeError:
                    pass

            if resolved:
                domain = "?"
                if dns.qd is not None:
                    qd_list = dns.qd if isinstance(dns.qd, list) else [dns.qd]
                    if qd_list and qd_list[0] is not None:
                        domain = _decode_dns_name(qd_list[0].qname).rstrip(".")
                queries.append({
                    "domain": domain,
                    "type": "response",
                    "resolved_to": resolved,
                    "timestamp": float(pkt.time),
                    "direction": "response",
                })

    return queries


# ── TLS extraction ────────────────────────────────────────────────────────

def _extract_tls(packets) -> list[dict]:
    handshakes: list[dict] = []

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if len(payload) < 6:
            continue

        if payload[0] != 0x16:
            continue

        try:
            handshake_type = payload[5]
        except IndexError:
            continue

        if handshake_type == 0x01:
            sni = _extract_sni(payload)
            cipher_suites = _extract_cipher_suites(payload)
            handshakes.append({
                "type": "client_hello",
                "src": f"{ip.src}:{tcp.sport}",
                "dst": f"{ip.dst}:{tcp.dport}",
                "sni": sni or "unknown",
                "cipher_suites": cipher_suites[:5],
                "timestamp": float(pkt.time),
            })
        elif handshake_type == 0x02:
            cs = _extract_server_cipher(payload)
            handshakes.append({
                "type": "server_hello",
                "src": f"{ip.src}:{tcp.sport}",
                "dst": f"{ip.dst}:{tcp.dport}",
                "cipher_suite": cs,
                "timestamp": float(pkt.time),
            })
        elif handshake_type == 0x0B:
            cert_fingerprint = _extract_cert_fingerprint(payload)
            if cert_fingerprint:
                subject, fp = cert_fingerprint
                handshakes.append({
                    "type": "certificate",
                    "src": f"{ip.src}:{tcp.sport}",
                    "dst": f"{ip.dst}:{tcp.dport}",
                    "subject": subject[:120],
                    "fingerprint_sha1": fp,
                    "timestamp": float(pkt.time),
                })

    return handshakes


def _extract_sni(payload: bytes) -> str | None:
    try:
        pos = 43
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        if pos + 1 > len(payload):
            return None
        compression_len = payload[pos]
        pos += 1 + compression_len

        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        end = pos + extensions_len

        while pos + 4 <= end:
            ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:
                if pos + 2 > len(payload):
                    return None
                _ = struct.unpack(">H", payload[pos:pos + 2])[0]
                pos += 2
                if pos >= len(payload):
                    return None
                sni_type = payload[pos]
                pos += 1
                if pos + 2 > len(payload):
                    return None
                sni_len = struct.unpack(">H", payload[pos:pos + 2])[0]
                pos += 2
                if sni_type == 0x00 and pos + sni_len <= len(payload):
                    return payload[pos:pos + sni_len].decode(errors="replace")

            pos += ext_len
    except Exception:
        pass
    return None


def _extract_cipher_suites(payload: bytes) -> list[str]:
    try:
        pos = 43
        if pos >= len(payload):
            return []
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return []
        cs_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        cs_data = payload[pos:pos + cs_len]
        suites = []
        for i in range(0, len(cs_data), 2):
            cs = struct.unpack(">H", cs_data[i:i + 2])[0]
            suites.append(hex(cs))
        return suites
    except Exception:
        return []


def _extract_server_cipher(payload: bytes) -> str:
    try:
        cs = struct.unpack(">H", payload[9:11])[0]
        return hex(cs)
    except Exception:
        return "unknown"


def _extract_cert_fingerprint(payload: bytes) -> tuple[str, str] | None:
    try:
        pos = 6
        if pos + 3 > len(payload):
            return None

        certs_len = struct.unpack(">I", b"\x00" + payload[pos:pos + 3])[0]
        pos += 3
        end = pos + certs_len

        while pos + 3 < end:
            cert_len = struct.unpack(">I", b"\x00" + payload[pos:pos + 3])[0]
            pos += 3
            if pos + cert_len > len(payload):
                break

            cert_der = payload[pos:pos + cert_len]
            fp = hashlib.sha1(cert_der).hexdigest()

            subject = _extract_cert_subject(cert_der)

            pos += cert_len
            return subject, fp
    except Exception:
        pass
    return None


def _extract_cert_subject(der_data: bytes) -> str:
    try:
        cn_marker = b"\x06\x03\x55\x04\x03"
        idx = der_data.find(cn_marker)
        if idx >= 0:
            start = idx + len(cn_marker)
            hdr = der_data[start]
            if hdr < 0x80:
                length = hdr
                return der_data[start + 1:start + 1 + length].decode(
                    "utf-8", errors="replace"
                )
    except Exception:
        pass
    return "unknown"


# ── Connection tracking ───────────────────────────────────────────────────

def _extract_connections(packets) -> list[dict]:
    conns: dict[tuple, dict] = {}

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)
        ordered = src < dst
        conn_key: tuple = (
            ip.src if ordered else ip.dst,
            ip.dst if ordered else ip.src,
            tcp.sport if ordered else tcp.dport,
            tcp.dport if ordered else tcp.sport,
        )

        if conn_key not in conns:
            conns[conn_key] = {
                "src_ip": ip.src if ordered else ip.dst,
                "dst_ip": ip.dst if ordered else ip.src,
                "src_port": tcp.sport if ordered else tcp.dport,
                "dst_port": tcp.dport if ordered else tcp.sport,
                "start_time": float(pkt.time),
                "end_time": float(pkt.time),
                "duration": 0.0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets": 0,
                "syn": bool(tcp.flags & 0x02),
                "syn_ack": False,
                "fin": bool(tcp.flags & 0x01),
                "rst": bool(tcp.flags & 0x04),
            }

        c = conns[conn_key]
        c["end_time"] = float(pkt.time)
        c["packets"] += 1

        payload_len = max(len(bytes(tcp.payload)) - (4 if tcp.flags & 0x08 else 0), 0)

        if ordered:
            c["bytes_sent"] += payload_len
        else:
            c["bytes_recv"] += payload_len

        if tcp.flags & 0x12 == 0x12:
            c["syn_ack"] = True
        if tcp.flags & 0x01:
            c["fin"] = True
        if tcp.flags & 0x04:
            c["rst"] = True

    for c in conns.values():
        c["duration"] = round(c["end_time"] - c["start_time"], 3)

    return list(conns.values())


# ── Data volume ───────────────────────────────────────────────────────────

def _calc_data_volume(packets) -> list[dict]:
    flow_volumes: dict[tuple, dict] = defaultdict(
        lambda: {"bytes_forward": 0, "bytes_reverse": 0, "syn_src": None}
    )

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload_len = max(len(bytes(tcp.payload)), 0)

        a = (ip.src, tcp.sport)
        b = (ip.dst, tcp.dport)
        flow_key = (a, b) if a < b else (b, a)

        direction_forward = a < b

        if flow_volumes[flow_key]["syn_src"] is None and (tcp.flags & 0x02):
            flow_volumes[flow_key]["syn_src"] = a

        if direction_forward:
            flow_volumes[flow_key]["bytes_forward"] += payload_len
        else:
            flow_volumes[flow_key]["bytes_reverse"] += payload_len

    host_volumes: dict[str, dict] = defaultdict(
        lambda: {"bytes_sent": 0, "bytes_recv": 0, "connections": set()}
    )

    for flow_key, data in flow_volumes.items():
        if data["syn_src"] is not None:
            client = data["syn_src"]
            server = flow_key[0] if flow_key[0] != client else flow_key[1]
        else:
            client = flow_key[0]
            server = flow_key[1]

        server_str = f"{server[0]}:{server[1]}"

        if client == flow_key[0]:
            sent = data["bytes_forward"]
            recv = data["bytes_reverse"]
        else:
            sent = data["bytes_reverse"]
            recv = data["bytes_forward"]

        host_volumes[server_str]["bytes_sent"] += sent
        host_volumes[server_str]["bytes_recv"] += recv

    result = []
    for host, data in sorted(
        host_volumes.items(), key=lambda x: -(x[1]["bytes_sent"] + x[1]["bytes_recv"])
    ):
        result.append({
            "destination": host,
            "bytes_sent": data["bytes_sent"],
            "bytes_recv": data["bytes_recv"],
            "total": data["bytes_sent"] + data["bytes_recv"],
        })
    return result


# ── Beaconing detection ───────────────────────────────────────────────────

def _detect_beaconing(packets) -> list[dict]:
    dest_timestamps: dict[str, list[float]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            dst = f"{ip.dst}:{tcp.dport}"
            dest_timestamps[dst].append(float(pkt.time))

    findings: list[dict] = []
    for dst, timestamps in dest_timestamps.items():
        if len(timestamps) < MIN_BEACON_SAMPLES:
            continue

        timestamps.sort()
        gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not gaps:
            continue

        mean_gap = sum(gaps) / len(gaps)
        if len(gaps) > 1:
            variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            std_dev = variance ** 0.5
        else:
            std_dev = 0.0

        cv = std_dev / mean_gap if mean_gap > 0 else 0.0

        if cv < BEACON_CV_THRESHOLD and len(timestamps) >= MIN_BEACON_SAMPLES:
            findings.append({
                "destination": dst,
                "connection_count": len(timestamps),
                "interval_mean_s": round(mean_gap, 2),
                "interval_std_s": round(std_dev, 2),
                "coefficient_of_variation": round(cv, 2),
            })

    return sorted(findings, key=lambda x: -x["connection_count"])


# ── Non-HTTP protocol detection ───────────────────────────────────────────

HTTP_PORTS = {80, 443, 8080, 8443, 8000}


def _detect_non_http(packets) -> list[dict]:
    seen: set[tuple] = set()
    connections: list[dict] = []

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            continue

        if tcp.dport in HTTP_PORTS:
            continue

        conn_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if conn_key in seen:
            continue
        seen.add(conn_key)

        connections.append({
            "src": f"{ip.src}:{tcp.sport}",
            "dst": f"{ip.dst}:{tcp.dport}",
            "port": tcp.dport,
            "protocol": _guess_protocol(tcp.dport),
        })

    return connections


def _guess_protocol(port: int) -> str:
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 110: "POP3", 123: "NTP", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 445: "SMB", 465: "SMTPS",
        514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        2049: "NFS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        27017: "MongoDB",
    }
    return common_ports.get(port, f"TCP-{port}")


# ── Findings generation ───────────────────────────────────────────────────

def _generate_findings(
    dns_queries: list[dict],
    tls_handshakes: list[dict],
    connections: list[dict],
    data_volume: list[dict],
    beaconing: list[dict],
    non_http: list[dict],
) -> list[dict]:
    findings: list[dict] = []
    seen_domains: set[str] = set()
    seen_destinations: set[str] = set()

    for dns in dns_queries:
        domain = dns.get("domain", "")
        if not domain or not dns.get("direction") == "query":
            continue

        tld_section = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld_section in SUSPICIOUS_TLDS and domain not in seen_domains:
            seen_domains.add(domain)
            findings.append({
                "type": "suspicious_tld",
                "severity": "MEDIUM",
                "detail": f"DNS query to suspicious TLD: {domain}",
                "domain": domain,
            })

    for b in beaconing:
        dst = b["destination"]
        if dst in seen_destinations:
            continue
        seen_destinations.add(dst)
        cv = b["coefficient_of_variation"]

        if cv < 0.3 and b["connection_count"] >= 5:
            findings.append({
                "type": "beaconing",
                "severity": "HIGH",
                "detail": (
                    f"Regular beaconing to {dst}: "
                    f"{b['connection_count']} connections, "
                    f"mean interval {b['interval_mean_s']}s, "
                    f"CV={cv}"
                ),
                "destination": dst,
                "interval_mean_s": b["interval_mean_s"],
                "connection_count": b["connection_count"],
            })
        elif cv < BEACON_CV_THRESHOLD:
            findings.append({
                "type": "beaconing",
                "severity": "MEDIUM",
                "detail": (
                    f"Suspicious timing pattern to {dst}: "
                    f"{b['connection_count']} connections, "
                    f"mean interval {b['interval_mean_s']}s, "
                    f"CV={cv}"
                ),
                "destination": dst,
                "interval_mean_s": b["interval_mean_s"],
                "connection_count": b["connection_count"],
            })

    for dv in data_volume:
        if dv["bytes_recv"] > EXFIL_THRESHOLD:
            findings.append({
                "type": "large_transfer",
                "severity": "MEDIUM",
                "detail": (
                    f"Large download from {dv['destination']}: "
                    f"{dv['bytes_recv'] / 1024:.1f} KB "
                    f"({dv['connection_count']} connection(s))"
                ),
                "destination": dv["destination"],
                "bytes": dv["bytes_recv"],
            })

    for n in non_http:
        if n["port"] == 8080:
            continue
        findings.append({
            "type": "non_http_protocol",
            "severity": "MEDIUM" if n["port"] in (22, 23, 3389) else "LOW",
            "detail": (
                f"Non-HTTP connection to {n['dst']} "
                f"({n['protocol']})"
            ),
            "destination": n["dst"],
            "protocol": n["protocol"],
            "port": n["port"],
        })

    rapid = _find_rapid_connections(connections)
    for r in rapid:
        findings.append({
            "type": "rapid_connections",
            "severity": "LOW",
            "detail": (
                f"Rapid connections to {r['destination']}: "
                f"{r['count']} connections in {r['window_secs']}s "
                f"(mean gap {r['mean_gap_ms']:.0f}ms)"
            ),
            "destination": r["destination"],
            "count": r["count"],
        })

    return findings


def _find_rapid_connections(connections: list[dict]) -> list[dict]:
    dest_times: dict[str, list[float]] = defaultdict(list)
    for c in connections:
        dest = f"{c['dst_ip']}:{c['dst_port']}"
        dest_times[dest].append(c["start_time"])

    findings: list[dict] = []
    for dest, times in dest_times.items():
        if len(times) < 3:
            continue
        times.sort()
        gaps = [(times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1)]
        mean_gap = sum(gaps) / len(gaps)

        if mean_gap < RAPID_CONN_MS:
            window = times[-1] - times[0]
            findings.append({
                "destination": dest,
                "count": len(times),
                "window_secs": round(window, 1),
                "mean_gap_ms": round(mean_gap, 1),
            })

    return findings

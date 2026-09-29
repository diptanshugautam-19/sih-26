"""
scripts/generate_c2_pcap.py

Generates a realistic, standard-compliant PCAP file for the preset:
"Zero-Day C2 HTTPS Beacon Tunnel" (c2_beacon_https_tunnel.pcap)

Features:
- Microsecond libpcap format (magic: 0xa1b2c3d4 / 0xd4c3b2a1)
- Ethernet II + IPv4 + TCP/UDP frames
- Periodic Cobalt Strike Malleable C2 HTTPS beaconing (Port 443) with low jitter (<1.2%)
- Covert DNS TXT record tunneling queries (Port 53)
- Realistic TLS 1.3 ClientHello, ServerHello, and ApplicationData records
"""

import os
import struct
import random
import socket
from pathlib import Path


def ip2bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)


def mac2bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int = 1) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000  # Don't fragment
    ttl = 64
    src_b = ip2bytes(src_ip)
    dst_b = ip2bytes(dst_ip)
    hdr_no_cksum = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src_b, dst_b)
    cksum = checksum(hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, cksum, src_b, dst_b)
    return ip_hdr + payload


def build_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    data_offset = (5 << 4)
    tcp_hdr_no_cksum = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset, flags, window, 0, 0)
    # Pseudo header for TCP checksum
    src_b = ip2bytes(src_ip)
    dst_b = ip2bytes(dst_ip)
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 6, len(tcp_hdr_no_cksum) + len(payload))
    cksum = checksum(pseudo + tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset, flags, window, cksum, 0)
    return tcp_hdr + payload


def build_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    src_b = ip2bytes(src_ip)
    dst_b = ip2bytes(dst_ip)
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 17, length)
    udp_hdr_no_cksum = struct.pack("!HHHH", sport, dport, length, 0)
    cksum = checksum(pseudo + udp_hdr_no_cksum + payload)
    if cksum == 0:
        cksum = 0xFFFF
    udp_hdr = struct.pack("!HHHH", sport, dport, length, cksum)
    return udp_hdr + payload


def build_ethernet_frame(src_mac: str, dst_mac: str, ip_packet: bytes) -> bytes:
    eth_hdr = struct.pack("!6s6sH", mac2bytes(dst_mac), mac2bytes(src_mac), 0x0800)
    return eth_hdr + ip_packet


def build_tls13_application_data(payload_len: int = 512) -> bytes:
    # TLS 1.3 Record: Type=23 (0x17), Version=0x0303 (TLS 1.2 compatibility layer for 1.3)
    header = struct.pack("!BHH", 0x17, 0x0303, payload_len)
    data = os.urandom(payload_len)
    return header + data


def build_tls_client_hello() -> bytes:
    content = b"\x01\x00\x01\xfc\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + b"\x00\x22\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\x00\x9e\x00\x9c"
    record = struct.pack("!BHH", 0x16, 0x0301, len(content)) + content
    return record


def build_tls_server_hello() -> bytes:
    content = b"\x02\x00\x00\x7a\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + b"\x13\x01\x00"
    record = struct.pack("!BHH", 0x16, 0x0303, len(content)) + content
    return record


def generate_c2_pcap(output_path: str, num_beacon_cycles: int = 120):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # PCAP Global Header: standard little-endian libpcap
    # magic=0xa1b2c3d4, major=2, minor=4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    victim_ip = "10.0.0.31"       # DB-02 / Customer Ledger Server
    c2_ip = "185.220.101.4"       # External Bulletproof C2
    dns_ip = "10.0.0.15"          # SRV-DC01
    corp_mac = "00:50:56:a1:00:1f"
    gw_mac = "00:50:56:00:00:01"
    c2_mac = "00:50:56:ff:ee:04"

    start_timestamp = 1790610000.0  # Epoch base
    current_time = start_timestamp

    packets = []  # list of (ts_sec, ts_usec, raw_bytes)

    beacon_interval = 2.0  # 2.0 seconds nominal beacon frequency
    jitter = 0.012         # 1.2% Cobalt Strike Malleable jitter

    ident = 1000

    print(f"Generating C2 HTTPS Beacon Tunnel trace ({num_beacon_cycles} beacon cycles)...")

    for cycle in range(num_beacon_cycles):
        # 1. Covert DNS TXT Query for heartbeat
        dns_sport = random.randint(49152, 65535)
        ident += 1
        query_id = random.randint(1000, 65000)
        subdomain = f"v{cycle:03d}-c2b-{random.randint(10000, 99999)}.telemetry-sync.darkops.net"
        
        # Build simple DNS query payload
        dns_payload = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        for part in subdomain.split("."):
            dns_payload += struct.pack("!B", len(part)) + part.encode("ascii")
        dns_payload += b"\x00" + struct.pack("!HH", 16, 1)  # TXT record query (type 16, class 1)
        
        udp_req = build_udp_packet(victim_ip, dns_ip, dns_sport, 53, dns_payload)
        eth_dns_req = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, dns_ip, 17, udp_req, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_dns_req))
        current_time += 0.004

        # DNS Response
        ident += 1
        dns_resp = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + dns_payload[12:]
        txt_answer = b"\x20" + os.urandom(32)  # 32-byte encrypted C2 instruction in TXT record
        dns_resp += struct.pack("!HHHIH", 0xc00c, 16, 1, 60, len(txt_answer)) + txt_answer
        udp_ans = build_udp_packet(dns_ip, victim_ip, 53, dns_sport, dns_resp)
        eth_dns_ans = build_ethernet_frame(gw_mac, corp_mac, build_ipv4_packet(dns_ip, victim_ip, 17, udp_ans, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_dns_ans))
        current_time += 0.008

        # 2. TLS 1.3 HTTPS Beacon Session to 185.220.101.4:443
        tcp_sport = 51000 + (cycle % 1000)
        seq_cli = random.randint(100000, 900000)
        seq_srv = random.randint(100000, 900000)

        # TCP SYN
        ident += 1
        syn = build_tcp_packet(victim_ip, c2_ip, tcp_sport, 443, seq_cli, 0, 0x02)
        eth_syn = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, c2_ip, 6, syn, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_syn))
        current_time += 0.015

        # TCP SYN-ACK
        ident += 1
        seq_cli += 1
        synack = build_tcp_packet(c2_ip, victim_ip, 443, tcp_sport, seq_srv, seq_cli, 0x12)
        eth_synack = build_ethernet_frame(gw_mac, corp_mac, build_ipv4_packet(c2_ip, victim_ip, 6, synack, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_synack))
        current_time += 0.001

        # TCP ACK
        seq_srv += 1
        ack = build_tcp_packet(victim_ip, c2_ip, tcp_sport, 443, seq_cli, seq_srv, 0x10)
        eth_ack = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, c2_ip, 6, ack, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_ack))
        current_time += 0.005

        # TLS Client Hello
        client_hello = build_tls_client_hello()
        psh1 = build_tcp_packet(victim_ip, c2_ip, tcp_sport, 443, seq_cli, seq_srv, 0x18, client_hello)
        eth_psh1 = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, c2_ip, 6, psh1, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_psh1))
        seq_cli += len(client_hello)
        current_time += 0.012

        # TLS Server Hello
        server_hello = build_tls_server_hello()
        psh2 = build_tcp_packet(c2_ip, victim_ip, 443, tcp_sport, seq_srv, seq_cli, 0x18, server_hello)
        eth_psh2 = build_ethernet_frame(gw_mac, corp_mac, build_ipv4_packet(c2_ip, victim_ip, 6, psh2, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_psh2))
        seq_srv += len(server_hello)
        current_time += 0.005

        # Encrypted Application Data Bursts (Simulated Cobalt Strike Malleable Data Exchange)
        num_bursts = random.randint(2, 6)
        for _ in range(num_bursts):
            # Client sends encrypted exfil / heartbeat (length 256 to 1400)
            data_out = build_tls13_application_data(random.randint(300, 1200))
            p_out = build_tcp_packet(victim_ip, c2_ip, tcp_sport, 443, seq_cli, seq_srv, 0x18, data_out)
            eth_p_out = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, c2_ip, 6, p_out, ident))
            sec = int(current_time)
            usec = int((current_time - sec) * 1_000_000)
            packets.append((sec, usec, eth_p_out))
            seq_cli += len(data_out)
            current_time += random.uniform(0.002, 0.008)

            # C2 server responds with encrypted command tasking
            data_in = build_tls13_application_data(random.randint(150, 600))
            p_in = build_tcp_packet(c2_ip, victim_ip, 443, tcp_sport, seq_srv, seq_cli, 0x18, data_in)
            eth_p_in = build_ethernet_frame(gw_mac, corp_mac, build_ipv4_packet(c2_ip, victim_ip, 6, p_in, ident))
            sec = int(current_time)
            usec = int((current_time - sec) * 1_000_000)
            packets.append((sec, usec, eth_p_in))
            seq_srv += len(data_in)
            current_time += random.uniform(0.002, 0.008)

        # Connection Teardown (FIN-ACK)
        fin = build_tcp_packet(victim_ip, c2_ip, tcp_sport, 443, seq_cli, seq_srv, 0x11)
        eth_fin = build_ethernet_frame(corp_mac, gw_mac, build_ipv4_packet(victim_ip, c2_ip, 6, fin, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_fin))
        current_time += 0.004

        finack = build_tcp_packet(c2_ip, victim_ip, 443, tcp_sport, seq_srv, seq_cli + 1, 0x11)
        eth_finack = build_ethernet_frame(gw_mac, corp_mac, build_ipv4_packet(c2_ip, victim_ip, 6, finack, ident))
        sec = int(current_time)
        usec = int((current_time - sec) * 1_000_000)
        packets.append((sec, usec, eth_finack))

        # Sleep interval with <1.2% jitter
        actual_sleep = beacon_interval + random.uniform(-beacon_interval * jitter, beacon_interval * jitter)
        current_time += actual_sleep

    # Write PCAP file
    with open(output_path, "wb") as f:
        f.write(global_hdr)
        for sec, usec, raw in packets:
            hdr = struct.pack("<IIII", sec, usec, len(raw), len(raw))
            f.write(hdr)
            f.write(raw)

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Successfully generated {output_path} ({len(packets)} packets, {file_size_mb:.2f} MB)")
    return len(packets), file_size_mb


if __name__ == "__main__":
    out_file = Path("data/pcaps_sample/c2_beacon_https_tunnel.pcap")
    generate_c2_pcap(str(out_file), num_beacon_cycles=150)

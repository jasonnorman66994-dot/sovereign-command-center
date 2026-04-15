#!/usr/bin/env python3
"""
Packet Sniffer & Network Analyzer
==================================
Captures and analyzes network packets with protocol dissection.
Requires administrator/root privileges.
For authorized use only on your own network.
"""

import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PacketInfo:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ""
    info: str = ""
    raw: bytes = b""


# Protocol numbers
PROTOCOLS = {
    1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    89: "OSPF", 132: "SCTP",
}

# TCP flags
TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
}

# Common ports for display
PORT_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-PROXY",
}


def parse_ethernet(raw_data: bytes):
    """Parse Ethernet frame header."""
    if len(raw_data) < 14:
        return None, None, None
    dest_mac = raw_data[:6]
    src_mac = raw_data[6:12]
    proto = struct.unpack("!H", raw_data[12:14])[0]
    return format_mac(dest_mac), format_mac(src_mac), proto


def format_mac(mac_bytes: bytes) -> str:
    """Format MAC address bytes to string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_ipv4(raw_data: bytes):
    """Parse IPv4 header."""
    if len(raw_data) < 20:
        return None
    version_ihl = raw_data[0]
    ihl = (version_ihl & 0x0F) * 4
    total_length = struct.unpack("!H", raw_data[2:4])[0]
    ttl = raw_data[8]
    protocol = raw_data[9]
    src_ip = socket.inet_ntoa(raw_data[12:16])
    dst_ip = socket.inet_ntoa(raw_data[16:20])
    return {
        "ihl": ihl, "total_length": total_length, "ttl": ttl,
        "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
        "data": raw_data[ihl:],
    }


def parse_tcp(raw_data: bytes):
    """Parse TCP header."""
    if len(raw_data) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", raw_data[:4])
    seq_num = struct.unpack("!I", raw_data[4:8])[0]
    ack_num = struct.unpack("!I", raw_data[8:12])[0]
    offset_flags = struct.unpack("!H", raw_data[12:14])[0]
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x3F

    flag_str = " ".join(name for bit, name in TCP_FLAGS.items() if flags & bit)

    return {
        "src_port": src_port, "dst_port": dst_port,
        "seq": seq_num, "ack": ack_num,
        "flags": flag_str, "data": raw_data[offset:],
    }


def parse_udp(raw_data: bytes):
    """Parse UDP header."""
    if len(raw_data) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", raw_data[:6])
    return {
        "src_port": src_port, "dst_port": dst_port,
        "length": length, "data": raw_data[8:],
    }


def parse_icmp(raw_data: bytes):
    """Parse ICMP header."""
    if len(raw_data) < 8:
        return None
    icmp_type, code, checksum = struct.unpack("!BBH", raw_data[:4])

    type_names = {
        0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
        8: "Echo Request", 11: "Time Exceeded", 30: "Traceroute",
    }
    return {
        "type": icmp_type, "code": code,
        "type_name": type_names.get(icmp_type, f"Type {icmp_type}"),
        "data": raw_data[8:],
    }


def hex_dump(data: bytes, length: int = 16) -> str:
    """Generate hex dump of data."""
    lines = []
    for i in range(0, min(len(data), 256), length):
        chunk = data[i:i + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  │  {i:04x}  {hex_part:<{length * 3}}  {ascii_part}")
    return "\n".join(lines)


def format_port(port: int) -> str:
    """Format port with service name."""
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def print_packet(pkt: PacketInfo, show_hex: bool = False, packet_num: int = 0):
    """Print a single packet."""
    color_map = {
        "TCP": "\033[92m",   # Green
        "UDP": "\033[94m",   # Blue
        "ICMP": "\033[93m",  # Yellow
    }
    reset = "\033[0m"
    color = color_map.get(pkt.protocol, "\033[97m")

    src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
    dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip

    flags = f" [{pkt.flags}]" if pkt.flags else ""
    info = f" {pkt.info}" if pkt.info else ""

    print(f"  {color}#{packet_num:<5} {pkt.timestamp} {pkt.protocol:<5} "
          f"{src:<22} → {dst:<22} len={pkt.length}{flags}{info}{reset}")

    if show_hex and pkt.raw:
        print(hex_dump(pkt.raw))
        print()


def run_sniffer(args):
    """Main sniffer entry point."""
    max_packets = args.count
    show_hex = args.hex
    output_file = args.output
    bpf_filter = args.filter

    print("  [*] Packet Sniffer - Shadow Toolkit")
    print("  [*] Requires administrator/root privileges")
    print()

    # Platform-specific raw socket
    if sys.platform == "win32":
        try:
            # Windows raw socket
            interface = args.interface or socket.gethostbyname(socket.gethostname())
            print(f"  [*] Binding to: {interface}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((interface, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            is_windows = True
        except PermissionError:
            print("  [✗] Permission denied. Run as Administrator!")
            return
        except OSError as e:
            print(f"  [✗] Socket error: {e}")
            print("  [!] Try running as Administrator")
            return
    else:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if args.interface:
                sock.bind((args.interface, 0))
                print(f"  [*] Interface: {args.interface}")
            is_windows = False
        except PermissionError:
            print("  [✗] Permission denied. Run with sudo!")
            return
        except AttributeError:
            print("  [✗] AF_PACKET not available on this platform")
            return

    # Filter parsing (basic)
    filter_proto = None
    filter_port = None
    if bpf_filter:
        print(f"  [*] Filter: {bpf_filter}")
        parts = bpf_filter.lower().split()
        if "tcp" in parts:
            filter_proto = 6
        elif "udp" in parts:
            filter_proto = 17
        elif "icmp" in parts:
            filter_proto = 1
        if "port" in parts:
            idx = parts.index("port")
            if idx + 1 < len(parts):
                try:
                    filter_port = int(parts[idx + 1])
                except ValueError:
                    pass

    limit_str = str(max_packets) if max_packets > 0 else "unlimited"
    print(f"  [*] Capturing {limit_str} packets... (Ctrl+C to stop)")
    print()
    print(f"  {'#':<6} {'TIME':<15} {'PROTO':<6} {'SOURCE':<22}   {'DESTINATION':<22} INFO")
    print(f"  {'─' * 95}")

    packet_count = 0
    captured_data = []

    try:
        while True:
            if 0 < max_packets <= packet_count:
                break

            raw_data, _ = sock.recvfrom(65535)

            # Parse based on platform
            if is_windows:
                # Windows provides IP header directly
                ip = parse_ipv4(raw_data)
                offset = 0
            else:
                # Linux gives ethernet frame
                _, _, eth_proto = parse_ethernet(raw_data)
                if eth_proto != 0x0800:  # Not IPv4
                    continue
                ip = parse_ipv4(raw_data[14:])
                offset = 14

            if not ip:
                continue

            proto_num = ip["protocol"]
            proto_name = PROTOCOLS.get(proto_num, f"PROTO:{proto_num}")

            # Apply filter
            if filter_proto and proto_num != filter_proto:
                continue

            pkt = PacketInfo(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:12],
                src_ip=ip["src_ip"],
                dst_ip=ip["dst_ip"],
                protocol=proto_name,
                length=ip["total_length"],
                raw=ip["data"][:256],
            )

            # Protocol-specific parsing
            if proto_num == 6:  # TCP
                tcp = parse_tcp(ip["data"])
                if tcp:
                    pkt.src_port = tcp["src_port"]
                    pkt.dst_port = tcp["dst_port"]
                    pkt.flags = tcp["flags"]
                    pkt.info = f"seq={tcp['seq']} ack={tcp['ack']}"

                    if filter_port and tcp["src_port"] != filter_port and tcp["dst_port"] != filter_port:
                        continue

            elif proto_num == 17:  # UDP
                udp = parse_udp(ip["data"])
                if udp:
                    pkt.src_port = udp["src_port"]
                    pkt.dst_port = udp["dst_port"]
                    pkt.info = f"len={udp['length']}"

                    if filter_port and udp["src_port"] != filter_port and udp["dst_port"] != filter_port:
                        continue

            elif proto_num == 1:  # ICMP
                icmp = parse_icmp(ip["data"])
                if icmp:
                    pkt.info = f"{icmp['type_name']} (type={icmp['type']} code={icmp['code']})"

            packet_count += 1
            print_packet(pkt, show_hex=show_hex, packet_num=packet_count)

            if output_file:
                captured_data.append(raw_data)

    except KeyboardInterrupt:
        print(f"\n\n  [*] Capture stopped. {packet_count} packets captured.")

    finally:
        if is_windows:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        sock.close()

        if output_file and captured_data:
            # Save as simple binary dump (custom format)
            with open(output_file, "wb") as f:
                for pkt_data in captured_data:
                    length = len(pkt_data)
                    f.write(struct.pack("!I", length))
                    f.write(pkt_data)
            print(f"  [*] Saved {len(captured_data)} packets to {output_file}")

import struct
import socket
import binascii

from typing import Tuple

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))


def get_hex(binary: bytes) -> bytes:
    return binascii.hexlify(binary, "-")


def get_ip(ip: bytes) -> str:
    return socket.inet_ntoa(ip)


def parse_ethernet_header(raw_data: bytes) -> Tuple:
    dest, src, ptype = struct.unpack("!6s6sH", raw_data[:14])

    dest_mac = get_hex(dest)
    src_mac = get_hex(src)
    proto = socket.htons(ptype)
    data = raw_data[14:]

    return dest_mac, src_mac, proto, data


def parse_arp_header(raw_data: bytes) -> Tuple:
    (
        htype,
        ptype,
        hlen,
        plen,
        opcode,
        src_mac,
        src_ip,
        dest_mac,
        dest_ip,
    ) = struct.unpack("2s2s1s1s2s6s4s6s4s", raw_data)

    htype = get_hex(htype)
    ptype = get_hex(ptype)
    hlen = get_hex(hlen)
    plen = get_hex(plen)
    opcode = get_hex(opcode)
    src_mac = get_hex(src_mac)
    src_ip = get_ip(src_ip)
    dest_mac = get_hex(dest_mac)
    dest_ip = get_ip(dest_ip)

    return htype, ptype, hlen, plen, opcode, src_mac, src_ip, dest_mac, dest_ip


def print_arp_header(arp_header: Tuple, full: bool = False):
    (
        htype,
        ptype,
        hlen,
        plen,
        opcode,
        src_mac,
        src_ip,
        dest_mac,
        dest_ip,
    ) = arp_header

    if opcode == bytes("00-01", encoding="utf-8"):
        operation = "request"
    else:
        operation = "reply"

    if full:
        print("************************** ARP_PACKET_HEADER ************************")
        print(f"Hardware type:    {htype}")
        print(f"Protocol type:    {ptype}")
        print(f"Hardware size:    {hlen}")
        print(f"Protocol size:    {plen}")
        print(f"Operation:        {operation}")
        print(f"Source MAC:       {src_mac}")
        print(f"Source IP:        {src_ip}")
        print(f"Destination MAC:  {dest_mac}")
        print(f"Destination IP:   {dest_ip}")
        print("*********************************************************************\n")
    else:
        print("*************************** ARP_PACKET_INFO *************************")
        print(f"Protocol type:    {operation}")
        print(f"Source MAC:       {src_mac}")
        print(f"Destination MAC:  {dest_mac}")
        print("*********************************************************************\n")


if __name__ == "__main__":
    BUF_SIZE = 65535
    ARP_PROTO_DEC = 1544

    while True:
        raw_data, addr = s.recvfrom(BUF_SIZE)

        ethernet_header = parse_ethernet_header(raw_data)

        if ethernet_header[2] == ARP_PROTO_DEC:
            arp_header = parse_arp_header(raw_data[14:42])
            print_arp_header(arp_header)

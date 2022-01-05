import binascii
import socket
import struct

from typing import Tuple


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

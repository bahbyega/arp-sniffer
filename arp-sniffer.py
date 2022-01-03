import struct
import socket
import binascii

from mac_vendor_lookup import MacLookup

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))


def get_hex(address: bytes):
    return binascii.hexlify(address)


def parse_ethernet_header(raw_data: bytes):
    dest, src, ptype = struct.unpack("!6s6sH", raw_data[:14])

    dest_mac = get_hex(dest)
    src_mac = get_hex(src)
    proto = socket.htons(ptype)

    data = raw_data[14:]

    return dest_mac, src_mac, proto, data


def parse_arp_header(raw_data: bytes):
    return (get_hex(parsed) for parsed in struct.unpack("2s2s1s1s2s6s4s6s4s", raw_data))


def print_arp_header(arp_header):
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

    print("************************** ARP_PACKET_HEADER **************************")
    print(f"Hardware type:    {htype}")
    print(f"Protocol type:    {ptype}")
    print(f"Hardware size:    {hlen}")
    print(f"Protocol size:    {plen}")
    print(f"Operation:        {opcode}")
    print(f"Source MAC:       {src_mac}, manufacturer: {MacLookup().lookup(src_mac)}")
    print(f"Source IP:        {src_ip}")
    print(f"Destination MAC:  {dest_mac}, manufacturer: {MacLookup().lookup(dest_mac)}")
    print(f"Destination IP:   {dest_ip}")
    print("***********************************************************************\n")


while True:
    BUF_SIZE = 65535
    ARP_PROTO_DEC = 2054
    raw_data, addr = s.recvfrom(BUF_SIZE)

    ethernet_header = parse_ethernet_header(raw_data)

    if ethernet_header[2] == ARP_PROTO_DEC:
        arp_header = parse_arp_header(raw_data[14:42])
        print_arp_header(arp_header)

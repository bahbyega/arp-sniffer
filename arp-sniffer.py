import socket

from typing import Tuple

from oui_lookup import get_mac_vendor
from parser import parse_ethernet_header, parse_arp_header


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

    src_mac_manufacturer = get_mac_vendor(src_mac)
    dest_mac_manufacturer = get_mac_vendor(dest_mac)

    if full:
        print("************************** ARP_PACKET_HEADER ************************")
        print(f"Hardware type:    {htype}")
        print(f"Protocol type:    {ptype}")
        print(f"Hardware size:    {hlen}")
        print(f"Protocol size:    {plen}")
        print(f"Operation:        {operation}")
        print(f"Source MAC:       {src_mac}, man: {src_mac_manufacturer}")
        print(f"Source IP:        {src_ip}")
        print(f"Destination MAC:  {dest_mac}")
        print(f"Destination IP:   {dest_ip}, man: {dest_mac_manufacturer}")
        print("*********************************************************************\n")
    else:
        print("*************************** ARP_PACKET_INFO *************************")
        print(f"Protocol type:    {operation}")
        print(f"Source MAC:       {src_mac}, man: {src_mac_manufacturer}")
        print(f"Destination MAC:  {dest_mac}, man: {dest_mac_manufacturer}")
        print("*********************************************************************\n")


if __name__ == "__main__":
    BUF_SIZE = 65535
    ARP_PROTO_NUM = 1544

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    while True:
        raw_data, _ = sock.recvfrom(BUF_SIZE)
        ethernet_header = parse_ethernet_header(raw_data)

        if ethernet_header[2] == ARP_PROTO_NUM:
            arp_header = parse_arp_header(raw_data[14:42])
            print_arp_header(arp_header)

# ARP Sniffer 
ARP sniffer is a program which tracks received and sent ARP packets and displays information about them.
More about ARP can be found at [RFC 826](https://datatracker.ietf.org/doc/html/rfc826).

## Requirements
- Linux
- Python 3

## Usage
To run program use:
```
sudo python3 arp_sniffer.py
```
Which will start sniffing your network for ARP packets.

If you want to send ARP requests manually you can use such tools as `arping` or `nmap`.

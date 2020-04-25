#!/usr/bin/env python

import scapy.all as scapy
import optparse


def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	client_list = []
	for element in answered_list:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		client_list.append(client_dict)
	return client_list


def get_ip():
	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest="ip_address", help="IP address/IP range")
	captured_ip , arguments = parser.parse_args()
	return captured_ip


def print_result(results_list):
	print("IP\t\t\t MAC ADDRESS\n----------------------------------------------------")
	for client in results_list:
		print(client["ip"] + "\t\t" + client["mac"])


captured_ip = get_ip()
scan_result = scan(captured_ip.ip_address)
print_result(scan_result)





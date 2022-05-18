# Scapy package needed
from scapy.all import *

ports = [25, 53, 80, 443, 445, 8080, 8443]


def syn_scan(host):
    ans, _ = sr(IP(dst=host)/TCP(sport=5555, dport=ports, flags='S'), timeout=2, verbose=0)
    print(f'Open ports at {host}: ')
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)


def dns_scan(host):
    ans, _ = sr(IP(dst=host)/UDP(sport=5555, dport=53)/DNS(rd=1, qd=DNSQR(qname='google.com')), timeout=2, verbose=0)
    if ans:
        print(f'DNS Server at {host}')


ip = '8.8.8.8'
syn_scan(ip)
dns_scan(ip)

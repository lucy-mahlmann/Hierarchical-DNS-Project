from scapy.all import *
def parse_DNS(x):
    print (x.summary())
    print (DNS(x['Raw'].load).show())

sniff(prn=parse_DNS, iface='eth0', filter='port 53')

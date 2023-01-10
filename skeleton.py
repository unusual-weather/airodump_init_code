import pcap
import re
import dpkt
import socket
import time
import sys
                   

if len(sys.argv) !=2:
    exit(0)

sniffer = pcap.pcap(name=sys.argv[1],promisc=True,immediate=True,timeout_ms=1000) # name=eth, None 일경우 모든 default / promisc는 모든 eth에서 패킷 수집 

for ts, pkt in sniffer:
    flag = pkt[0x10:0x12]
    beacon = pkt[0x18:0x18+2]
    if (flag ==b'\xa0\x00') and (beacon ==b'\x80\x00'):
        try:
            print("-------Start--------")
            print('ESSID - ', end='', flush=True)
            print(pkt[0x3e:0x3e+pkt[0x3d]].decode('utf-8'))
            print('BSSID - ', end='', flush=True)
            print(':'.join('%02X' % i for i in pkt[0x22:0x22+6])) #패킷의 0번부터 5번 바이트까지 출력
            print("")
        except Exception as E:
            print("--------------------------ERROR-----------------------------------")
            print(E)
            print(pkt)
            break
    

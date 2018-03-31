#!/usr/bin/env python2
import pyshark
import struct
cap = pyshark.FileCapture('data.pcap')
with open("output.gif", "wb") as file:
for i in range(6970, 9195):
    packet = cap[i]
    if "icmp" in packet and '45.58.48.13' == packet.ip.dst:
        codeNum = int(packet.icmp.type)
        code = struct.pack("1B", codeNum)
        print codeNum
        file.write(code)

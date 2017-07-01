#! /usr/bin/python
import logging
import sys,getopt

'''
r = '\033[31m' #red
b = '\033[34m' #blue
g = '\033[32m' #green
y = '\033[33m' #yellow
m = '\033[34m' #magenta
c = '\033[36m' #cyan
'''

def main(argv):
	if len(sys.argv) < 5:
		print("\nInvalid Arguments")
		print(sys.argv[0], '-i <interface> -r <ip range>')
		sys.exit()


	interface=''
	ip_range=''

	try:
		opts, args = getopt.getopt(argv,"hi:r:",["iface=","ips="])
	except KeyInterrupt:
		print(sys.argv[0],'-i <interface> -r <ip range>')
		sys.exit(1)
	for opt,arg in opts:
		if opt=='-h':
			print('arp.py -i <interface> -r <ip range>')
			sys.exit()
		elif opt in ("-i","--iface"):
			interface=arg
		elif opt in ("-r","--ips"):
			ip_range=arg
		

	#print("\nScanning ...")
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	
	from scapy.all import srp,Ether,ARP,conf
	conf.verb=0
	ans,uans=srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip_range),timeout=2,iface=interface,inter=0.1)
	for snd,rcv in ans:
	        #print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
		print(rcv.sprintf("%ARP.psrc%"))
	#print("\nScan complete")



if __name__ == "__main__":
	main(sys.argv[1:])


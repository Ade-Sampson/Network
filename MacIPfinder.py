#!/usr/local/bin/python
#
#	Written by Ade Sampson 
#	
#	Program will detect all interfaces on machine, and will display 
#	the corresponding MAC and IP addresses for those interfaces.
#	
#	In order to identify online interfaces while scanning, this program
#	utilizes Scapy to create a range of IP addresses within the subnet
#	of the interface, then creates ARP packets with each of these addresses.
#	
#	The program will then read responses to these ARP requests, and will print
#	the IP addresses of the interfaces that responded to the console.
#
#
import ipaddress
import netifaces
from scapy.all import *

conf.verb = 0

addr = netifaces.interfaces()
print ("Interfaces: ")
for x in addr:
   print ("\t"+ x)
print("----\nInterface details:")
#################################################################################################
for x in addr:
   numaddr = netifaces.ifaddresses(x)
   notrealinterface = 0
   try:
        ipaddr = numaddr[netifaces.AF_INET]      
   except: 
   	notrealinterface = 1
   if notrealinterface == 0:
   	cidr = ipaddress.IPv4Network((0,ipaddr[0]['netmask']))
   	macaddr = numaddr[netifaces.AF_LINK]
   	print(x + ":\tMAC = " + macaddr[0]['addr'] + "\tIP = " + ipaddr[0]['addr'] + "/" + str(cidr.prefixlen))
   else:
   	cidr = '0'
   	macaddr = numaddr[netifaces.AF_LINK]
   	print(x + ":\tMAC = " + macaddr[0]['addr'] + "\tIP = " + ipaddr[0]['addr'] + "/" + cidr)
print("----")
##################################################################################################
for x in addr:
	numaddr = netifaces.ifaddresses(x)
	notrealinterface = 0
	try:
		ipaddr = numaddr[netifaces.AF_INET]      
	except:
		notrealinterface = 1
	loop = ipaddress.IPv4Address(ipaddr[0]['addr'])
	cidr = ipaddress.IPv4Network((0,ipaddr[0]['netmask']))
	if loop.is_loopback == False:
		print("Scanning on interface " + x + "\n----")
		a = ARP(pdst = str(loop) + "/" + str(cidr.prefixlen))
		e = Ether(dst = 'FF:FF:FF:FF:FF:FF')
		pkt = e/a
		s, r = srp(pkt, timeout = 3)
		c = []
		for sent, received in s:
			c.append({'IP': received.psrc, 'MAC': received.hwsrc})
		print("Results:")
		for i in c:
			print("MAC = " + i['MAC'] + "\tIP = " + i['IP'])
		print("----")
print("finished")
		

		
		
		
		
		
		
		
		
		

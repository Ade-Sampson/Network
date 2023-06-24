#Nick Korotzer & Ade Sampson
import random
import socket
import sys
from scapy.all import *

conf.verb = 0


if len(sys.argv) > 4:
    print("Too many arguments.\n")
    exit()
elif len(sys.argv) < 4:
    print("Missing arguments.\n")
    exit()

if sys.argv[1] == 'T':
    print("Protocol TCP")
elif sys.argv[1] == 'U':
    print("Protocol UDP")
else:
    print("Invalid transport layer protocol.")
    exit()
decision = sys.argv[1]

try:
    host = sys.argv[2]
    socket.inet_aton(host)
    print(f"Target {host}")
except:
    print("Invalid IP address")
    exit()

portSplit = False

try:
    portRange = sys.argv[3]
    portList = []
    numList = []
    for _ in portRange:
        print("Got in A")
        if _ == "-":
            portList = portRange.split("-")
            print(portList)
            print(len(portList))
            if (len(portList) > 2):
                exit()
                print("Got in B")
            print("Got in C")
            if portList[1] == None:
                print("Got in D")
                break
            print("Got in DA")
            if int(portList[0]) < 1 or int(portList[1]) < 1:
                print("Port number must be more that 0")
                exit()
            print("Got in DB")
            if (portList[0] > portList[1]):
                print("Your port range is backward")
                exit()
            print("Got in E")
            numList = [*range(int(portList[0]), int(portList[1]) + 1)]
            print(f"Ports {portList[0]}-{portList[1]}")
            portSplit = True
            break
    if portSplit == False:
        numList.append(int(portRange))
except:
    print("Issue with Port Range")
    exit()

# Send SYN with random Src Port for each Dst port
numList = random.sample(numList, len(numList))
if decision == "T":
    print("TCP Scanning starts ...")
    for dst_port in numList:
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0)

        if resp is None:
            print(f"Port: [{dst_port}]\t Status: Filtered\tReason: No response")

        elif(resp.haslayer(TCP)):
            ttl = resp.ttl
            if(resp.getlayer(TCP).flags == 0x12):
                # Send a gratuitous RST to close the connection
                send_rst = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),timeout=1,verbose=0)
                print(f"Port: [{dst_port}]\t Status: Open\tReason: Received TCP SYN-ACK ttl {ttl}")

            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"Port: [{dst_port}]\t Status: Closed\tReason: Received reset ttl {ttl}")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
                print(f"Port: [{dst_port}]\t Status: Filtered\tReason: ICMP port unreachable")

elif decision == "U":
    for dst_port in numList:
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=host)/UDP(sport=src_port,dport=dst_port)/"payload",timeout=3,verbose=0)
        if resp is None:
            print(f"Port: [{dst_port}]\t Status: open|Filtered\tReason: No response")
        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
                print(f"Port: [{dst_port}]\t Status: Closed\tReason: ICMP port unreachable")
        elif(resp.haslayer(UDP)):
                print(f"Port: [{dst_port}]\t Status: Open\tReason: UDP response received")




#!/usr/bin/python -u
#Captures traffic and extracts payloads             
#Payloads prepended with time, Hostname, and IP
#Then saved to a file, which is then read
#by logstash
#

from scapy.all import *
import threading
import time
import random

from datetime import datetime

#for file storage
import os
import glob


fileName="/var/log/MIRRORED/syslog.log"
captureFilter="ip and udp and port 514 and not host 10.11.21.78"
interface="eth1"

messages=[]		#Message Buffer (Epoch IP Hostname Syslog-Message)
packets=[]		#Packet Buffer
IP2host={}		#Mappings of IPs to Hostnames (DNS Resolution) 
IPs=[]			#List of IPs don't exist in IP2host and need to be resolved
blacklist=[]		#List of IPs for which DNS resolution failed
packetCount = 0		#
running=1		#Test value to kill threads
DNSdelay = .5		#Minimum delay between outbound DNS requests (seconds)
DNSmaintSleep = 30	#Delay in IP2host refresh loop. IP2host pair is verified, and next entry is checked after delay of DNSmaintSleep seconds.


filter = ['%ASA-', 'Generic :', '-AN', '%LINEPROTO-5', 'IKEDBG/', '%ILPOWER-5', '%CDP-4-NATIVE_VLAN_MISMATCH', 'chewy', 'XR203', '%FWSM', 'XR10', 'XR40', 'CisACS', '%STACKMGR-4']

#Basic check of payload against filter list (Bypassed)
def filterCheck(payload):
	count = 0
	return 0
	for y in filter:
		if y in payload:
			count+=1
#	return count
	return 0

#Takes source IP from packet and checks for presence in IP2host. If not in IP2host, is added to IPs list to have address resolved and added to IP2host
#Used only at start, packets are dropped.
def learnDNS(packet):
	IP=packet["IP"].src
	if IP not in IP2host:
		if IP not in IPs:
			IPs.append(IP)	

#Verfies values in IP2host. Continuous loop
class maintDNS(threading.Thread):
        def __init__(self):
                threading.Thread.__init__(self)

        def run(self):
                global IP2host
                global blacklist
                global packets
                global IPs
                global running
                time.sleep(60)
                while (running != 0):
                        for ip, response in IP2host.items():
                                if (running != 1):
                                        exit()
                                date = datetime.now()
                                DNStime=response.split(":")[1]
                                year=int(DNStime.split("-")[0])
                                month=int(DNStime.split("-")[1])
                                day=int(DNStime.split("-")[2])
                                responseTime=datetime(year, month, day)
                                dif = date - responseTime
				rando = random.randrange(0,3)
				print ":::"+str(date)+":IP2host:"+str(len(IP2host))+":blacklist:"+str(len(blacklist))+":packets:"+str(len(packets))+":IPsWaiting:"+str(len(IPs))
				#Was used to enforce a random TTL of 1-4 days.
                                if (dif.days > 1+rando) :
					try:
	                                        IP2host[ip] = socket.gethostbyaddr(ip)[0].split(".")[0].upper()+":"+str(date.year)+"-"+str(date.month)+"-"+str(date.day)
					except:
						blacklist.append(ip)
						print "BLACKLIST - " + str(len(blacklist))
                                time.sleep(DNSmaintSleep)
				if (len(packets) > 33333):
					print ":OVERRUN:"
				#	packets = []
					for x in range(0, len(packets)-1000):
					    packets.pop()
					
					
			blacklist = []

#Takes IP address from IPs, resolves the address, and adds entry to IP2host
class mapIP(threading.Thread):
        def __init__(self):
                threading.Thread.__init__(self)

        def run(self):
                global IPs
                global IP2host
                global blacklist
                global running
                time.sleep(1)
                while (running != 0):
#                        print len(IPs)
			if (len(IPs) != 0):
#                               print len(messages)
				if IPs[0] not in IP2host:
					date = datetime.now()
					try:
						IP2host[IPs[0]] = socket.gethostbyaddr(IPs[0])[0].split(".")[0].upper()+":"+str(date.year)+"-"+str(date.month)+"-"+str(date.day)
#						print IPs[0] + " - " + IP2host[IPs[0]]
					except:
						blacklist.append(IPs[0])
						print "BLACKLIST - " + str(len(blacklist))
					time.sleep(DNSdelay)
				IPs.remove(IPs[0])
			else:
	                        time.sleep(.2)

#Takes packet from "packets". Checks against filter. Checks for DNS mapping in IP2host. Checks against blacklist. Processes packet
#Processing:	extracts epoch time of reception from packet.
#		Adds newline if needed, also handles fringe case ssylog message formats.
#		Creates "message" string of EpochTime IP Hostname and syslogMessage"
#		Appends "message" to messages list
class processPackets(threading.Thread):
        def __init__(self):
                threading.Thread.__init__(self)

        def run(self):
                global running
                global messages
		global packets
		global IP2host
		global blacklist
		global IPs
                time.sleep(2)
                while (running != 0):
			time.sleep(.1)
			while (len(packets) > 0) and (running != 0):
				try:
					payload=packets[0].load
				except:
					print "PAYLOADERROR"
					payload=" :( "
##				time.sleep(.0002)
				IP=packets[0]["IP"].src
				unixTime=str(packets[0].time).split(".")[0]
#				print unixTime
	#			print payload
#				print packets[0].time
				if (filterCheck(payload) < 1):
					if (IP in IP2host):
#						print str(len(packets)) + " " + str(len(IPs))
						if payload.endswith('\n'):
							messages.append(unixTime + " " + IP + " " + IP2host[IP].split(":")[0] + " " + payload)
				#			messages.append(IP + " " + IP2host[IP].split(":")[0] + " " + payload)
						else:
							if '\n' in payload:
								newpayload = payload.replace("\n-T", " -T")
								payload = newpayload.replace("\n", "")
							messages.append(unixTime + " " + IP + " " + IP2host[IP].split(":")[0] + " " + payload+'\n')
				#			messages.append(IP + " " + IP2host[IP].split(":")[0] + " " + payload+'\n')
					else:
						if (IP not in blacklist) and (IP not in IPs):
							IPs.append(IP)
							packets.append(packets[0])
							if (len(packets) < 10):
								time.sleep(.1)
				packets.remove(packets[0])
#				print "====" + str(len(packets))

#Takes "message" from messages list and send to write()
#Holdover from when script send data directly in batches of 1000
class sendData(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		global running
		global messages
		time.sleep(2)
		while (running != 0):
			if (len(messages) > 0):
				write(messages[0])
				messages.remove(messages[0])
			else:
				time.sleep(1)

#Writes messages to file
def write(toSend):
	try:
		with open(fileName, "a") as f:
			f.write(toSend)

	except:
		print "HANDLED"
		time.sleep(5)
		return 0
	finally:
		f.close()
	return 1


#called by sniff on packet reception and pushes packet on to packets list
def bufferPacket(packet):
	global packets
	packets.append(packet)

#Start Threads
thread0 = mapIP()
thread0.start()
thread3 = maintDNS()
thread3.start()
DNSdelay=.1
###populates DNS list before recording messages to prevent "packets" list from growing too large and causing OOM killer fun
###Filter: port 514 (syslog)
print "Starting Learning Process: Round 1"
sniff(count=3000, filter=captureFilter, prn=learnDNS, iface=interface, store=0)
time.sleep(1)
while (len(IPs) != 0):
        print "Learning: " + str(len(IPs)) + " IP Addresses Left"
        time.sleep(2)
time.sleep(10)



print str(len(IP2host))
thread1 = sendData()
thread1.start()
thread2 = processPackets()
thread2.start()
## Setup sniff, filtering for UDP/IP traffic on port 514
##Hands traffic to buffer packet.
sniff(filter=captureFilter, prn=bufferPacket, iface=interface, store=0)
running=0
time.sleep(3)
thread1.join()
thread2.join()
thread0.join()
thread3.join()


exit()

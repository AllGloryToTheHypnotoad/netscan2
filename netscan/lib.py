#!/usr/bin/env python

# import datetime		# time stamp
# import pcapy		# passive mapping
# import os			# check sudo
# import dpkt			# parse packets
# import binascii		# get MAC addr on ARP messages
# import netaddr		# ipv4/6 addresses, address space: 192.168.5.0/24
# # import pprint as pp # display info
# import commands		# arp-scan
# import requests		# mac api
# import socket		# ordering
# import sys			# get platform (linux or linux2)
import subprocess	# use commandline
# import random		# Pinger uses it when creating ICMP packets
# from awake import wol # wake on lan

"""
[kevin@Tardis test]$ ./pmap5.py -p test2.pcap -d

sudo tcpdump -s 0 -i en1 -w test.pcap
-s 0 will set the capture byte to its maximum i.e. 65535 and will not truncate
-i en1 captures Ethernet interface
-w test.pcap will create that pcap file

tcpdump -qns 0 -X -r osx.pcap

[kevin@Tardis tmp]$ sudo tcpdump -w osx.pcap
tcpdump: data link type PKTAP
tcpdump: listening on pktap, link-type PKTAP (Packet Tap), capture size 65535 bytes
^C4414 packets captured
4416 packets received by filter
0 packets dropped by kernel

"""

class Commands(object):
	"""
	Unfortunately the extremely simple/useful commands was depreciated in favor
	of the complex/confusing subprocess ... this aims to simplify.
	"""
	def getoutput(self,cmd):
		ans = subprocess.Popen([cmd], stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]
		return ans

#######################
# class DNS(object):
# 	def __init(self,udp)__:
# 		dns = dpkt.dns.DNS(udp.data)
# 		for rr in dns.an:
# 			h = self.getRecord(rr)
# 			print h

# class ARP(object):
# 	def __init__(self, arp):
# 		if arp.op == dpkt.arp.ARP_OP_REPLY:
# 			msg={'type':'arp', 'mac': self.add_colons_to_mac( binascii.hexlify(arp.sha) ),'ipv4':socket.inet_ntoa(arp.spa)}
# 			return msg
# 		else: return {}
#
# class mDNS(object):
# 	def __init__(self,udp):
# 		msg = {}
# 		try:
# 			mdns = dpkt.dns.DNS(udp.data)
# 		except dpkt.Error:
# 			#print 'dpkt.Error'
# 			return msg
# 		except (IndexError, TypeError):
# 			# dpkt shouldn't do this, but it does in some cases
# 			#print 'other error'
# 			return msg
#
# 		if mdns.qr != dpkt.dns.DNS_R: return msg
# 		if mdns.opcode != dpkt.dns.DNS_QUERY: return msg
# 		if mdns.rcode != dpkt.dns.DNS_RCODE_NOERR: return msg
#
# 		msg['type'] = 'mdns'
# 		ans = []
#
# 		for rr in mdns.an:
# 			h = self.getRecord(rr)
#
# 			# check if empty
# 			if h: ans.append( h )
#
# 		msg['rr'] = ans
# 		return msg
#
# 	def getRecord(self,rr):
# 		"""
# 		The response records (rr) in a dns packet all refer to the same host
# 		"""
# 		if	 rr.type == 1:	return {'type': 'a', 'ipv4': socket.inet_ntoa(rr.rdata),'hostname': rr.name}
# 		elif rr.type == 28: return {'type': 'aaaa', 'ipv6': socket.inet_ntop(socket.AF_INET6, rr.rdata), 'hostname': rr.name}
# 		elif rr.type == 5:	return {'type': 'cname', 'hostname': rr.name, 'cname': rr.cname}
# 		elif rr.type == 13: return {'type': 'hostinfo', 'hostname': rr.name, 'info': rr.rdata}
# 		elif rr.type == 33: return {'type': 'srv', 'hostname': rr.srvname, 'port': rr.port, 'srv': rr.name.split('.')[-3], 'proto': rr.name.split('.')[-2]}
# 		elif rr.type == 12: return {'type': 'ptr'}
# 		elif rr.type == 16: return {'type': 'txt'}
# 		elif rr.type == 10: return {'type': 'wtf'}
#
# class PacketDecoder(object):
# 	"""
# 	PacketDecoder reads dpkt packets and produces a dict with useful information in network
# 	recon. Not everything is currently used.
# 	eth:hw addr src,dst
# 	 - ipv4: ip addr src,dst
# 	   -- tcp: port src, dst; sequence num;
# 	   -- udp: port src, dst;
# 		 -- dns: opcode; rcode;
# 		   -- RR:
# 			 -- txt: ?
# 			 -- a: ipv4; hostname
# 			 -- aaaa: ipv6; hostname
# 			 -- ptr: ?
# 			 -- cname: ?
# 			 -- srv: hostname; service; protocol; port
# 		   -- Q:
# 	 - ipv6: ip addr src,dst; nxt
# 	   -- icnmpv6:
# 	"""
# 	def add_colons_to_mac(self, mac_addr) :
# 		"""
# 		This function accepts a 12 hex digit string and converts it to a colon
# 		separated string
# 		"""
# 		s = list()
# 		for i in range(12/2) :	# mac_addr should always be 12 chars, we work in groups of 2 chars
# 			s.append( mac_addr[i*2:i*2+2] )
# 		r = ":".join(s)
# 		return r
#
# 	def decode(self,eth):
# 		"""
# 		decode an ethernet packet. The dict returned indicates the type (arp,mdns,etc)
# 		which will indicate how to read/use the dict.
#
# 		in: ethernet pkt
# 		out: dict
# 		"""
# 		if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
# 			return ARP(eth.data)
#
# 		#elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
# 		elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
# 			ip = eth.data
# 			if ip.p == dpkt.ip.IP_PROTO_UDP:
# 				udp = ip.data
#
# 				# these aren't useful
# #				if udp.dport == 53: #DNS
# #					return DNS(udp.data)
#
# 				if udp.dport == 5353: # mDNS
# 					return mDNS(udp.data)
# 				else: return {}
# 			else: return {}

#########################
#
# def macLookup(mac):
# 	"""
# 	json responce from www.macvendorlookup.com:
#
# 	{u'addressL1': u'1 Infinite Loop',
# 	u'addressL2': u'',
# 	u'addressL3': u'Cupertino CA 95014',
# 	u'company': u'Apple',
# 	u'country': u'UNITED STATES',
# 	u'endDec': u'202412195315711',
# 	u'endHex': u'B817C2FFFFFF',
# 	u'startDec': u'202412178538496',
# 	u'startHex': u'B817C2000000',
# 	u'type': u'MA-L'}
# 	"""
# 	try:
# 		r = requests.get('http://www.macvendorlookup.com/api/v2/' + mac)
# 	except requests.exceptions.HTTPError as e:
# 		print "HTTPError:", e.message
# 		return {'company':'unknown'}
#
# 	if r.status_code == 204: # no content found, bad MAC addr
# 		print 'ERROR: Bad MAC addr:',mac
# 		return {'company':'unknown'}
# 	elif r.headers['content-type'] != 'application/json':
# 		print 'ERROR: Wrong content type:', r.headers['content-type']
# 		return {'company':'unknown'}
# 	a={}
#
# 	try:
# 		a = r.json()[0]
# 		#print 'GOOD:',r.status_code,r.headers,r.ok,r.text,r.reason
# 	except:
# 		print 'ERROR:',r.status_code,r.headers,r.ok,r.text,r.reason
# 		a = {'company':'unknown'}
#
# 	return a





####################################################

# class IP(object):
# 	"""
# 	Gets the IP and MAC addresses for the localhost
# 	"""
# 	ip = 'x'
# 	mac = 'x'
#
# 	def __init__(self):
# 		"""Everything is done in init(), don't call any methods, just access ip or mac."""
# 		self.mac = self.getHostMAC()
# 		self.ip = self.getHostIP()
#
# 	def getHostIP(self):
# 		"""
# 		Need to get the localhost IP address
# 		in: none
# 		out: returns the host machine's IP address
# 		"""
# 		host_name = socket.gethostname()
# 		if '.local' not in host_name: host_name = host_name + '.local'
# 		ip = socket.gethostbyname(host_name)
# 		return ip
#
# 	def getHostMAC(self,dev='en1'):
# 		"""
# 		Major flaw of NMAP doesn't allow you to get the localhost's MAC address, so this
# 		is a work around.
# 		in: none
# 		out: string of hex for MAC address 'aa:bb:11:22..' or empty string if error
# 		"""
# 		# this doesn't work, could return any network address (en0, en1, bluetooth, etc)
# 		#return ':'.join(re.findall('..', '%012x' % uuid.getnode()))
# 		mac = commands.getoutput("ifconfig " + dev + "| grep ether | awk '{ print $2 }'")
#
# 		# double check it is a valid mac address
# 		if len(mac) == 17 and len(mac.split(':')) == 6: return mac
#
# 		# nothing found
# 		return ''

########################################################

# def main():
#
# 	print('Hello and goodbye!')
#
#
# if __name__ == "__main__":
# 	main()

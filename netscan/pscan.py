#!/usr/bin/env python

import datetime		# time stamp
import pcapy		# passive mapping
import os			# check sudo
import dpkt			# parse packets
import binascii		# get MAC addr on ARP messages
import netaddr		# ipv4/6 addresses, address space: 192.168.5.0/24
import pprint as pp # display info
import commands		# arp-scan
import requests		# mac api
import socket		# ordering
import sys			# get platform (linux or linux2)
import subprocess	# use commandline
import random		# Pinger uses it when creating ICMP packets
from ipwhois import WhoIs
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


#######################
# class DNS(object):
#	 def __init(self,udp)__:
#		 dns = dpkt.dns.DNS(udp.data)
#		 for rr in dns.an:
#			 h = self.getRecord(rr)
#			 print h

class ARP(object):
	def __init__(self, arp):
		self.msg = {}
		if arp.op == dpkt.arp.ARP_OP_REPLY:
			self.msg={'type':'arp', 'mac': self.add_colons_to_mac( binascii.hexlify(arp.sha) ),'ipv4':socket.inet_ntoa(arp.spa)}
			return
		else: return

	def get(self):
		return self.msg

	def add_colons_to_mac(self, mac_addr) :
		"""
		This function accepts a 12 hex digit string and converts it to a colon
		separated string
		"""
		s = list()
		for i in range(12/2) :	# mac_addr should always be 12 chars, we work in groups of 2 chars
			s.append( mac_addr[i*2:i*2+2] )
		r = ":".join(s)
		return r

class mDNS(object):
	def __init__(self,udp):
		self.msg = {}
		try:
			mdns = dpkt.dns.DNS(udp.data)
		except dpkt.Error:
			# print 'mDNS dpkt.Error'
			return
		except (IndexError, TypeError):
			# dpkt shouldn't do this, but it does in some cases
			# print 'mDNS other error'
			return
		except:
			# print 'mDNS crap: ',sys.exc_info()
			# print udp
			return

		if mdns.qr != dpkt.dns.DNS_R: return
		if mdns.opcode != dpkt.dns.DNS_QUERY: return
		if mdns.rcode != dpkt.dns.DNS_RCODE_NOERR: return

		self.msg['type'] = 'mdns'
		ans = []

		for rr in mdns.an:
			h = self.getRecord(rr)

			# check if empty
			if h: ans.append( h )

		self.msg['rr'] = ans
		return

	def getRecord(self,rr):
		"""
		The response records (rr) in a dns packet all refer to the same host
		"""
		if	 rr.type == 1:	return {'type': 'a', 'ipv4': socket.inet_ntoa(rr.rdata),'hostname': rr.name}
		elif rr.type == 28: return {'type': 'aaaa', 'ipv6': socket.inet_ntop(socket.AF_INET6, rr.rdata), 'hostname': rr.name}
		elif rr.type == 5:	return {'type': 'cname', 'hostname': rr.name, 'cname': rr.cname}
		elif rr.type == 13: return {'type': 'hostinfo', 'hostname': rr.name, 'info': rr.rdata}
		elif rr.type == 33: return {'type': 'srv', 'hostname': rr.srvname, 'port': rr.port, 'srv': rr.name.split('.')[-3], 'proto': rr.name.split('.')[-2]}
		elif rr.type == 12: return {'type': 'ptr'}
		elif rr.type == 16: return {'type': 'txt'}
		elif rr.type == 10: return {'type': 'wtf'}

	def get(self):
		return self.msg

class PacketDecoder(object):
	"""
	PacketDecoder reads dpkt packets and produces a dict with useful information in network
	recon. Not everything is currently used.
	eth:hw addr src,dst
	 - ipv4: ip addr src,dst
	   -- tcp: port src, dst; sequence num;
	   -- udp: port src, dst;
		 -- dns: opcode; rcode;
		   -- RR:
			 -- txt: ?
			 -- a: ipv4; hostname
			 -- aaaa: ipv6; hostname
			 -- ptr: ?
			 -- cname: ?
			 -- srv: hostname; service; protocol; port
		   -- Q:
	 - ipv6: ip addr src,dst; nxt
	   -- icmpv6:
	"""
	ipMap = {}
	def getip(self,ip,ipv6=False):
		if ipv6:
			return socket.inet_ntop(socket.AF_INET6, ip)
		else:
			return socket.inet_ntoa(ip)

	def decode(self,eth):
		"""
		decode an ethernet packet. The dict returned indicates the type (arp,mdns,etc)
		which will indicate how to read/use the dict.

		https://support.apple.com/en-us/HT202944

		in: ethernet pkt
		out: dict
		"""
		if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
			# print 'arp'
			return ARP(eth.data).get()

		elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
			ip = eth.data
			if ip.p == dpkt.ip.IP_PROTO_UDP:
				udp = ip.data

				# multicast is just like IPv4
				if udp.dport == 5353:
					# print udp
					ans = mDNS(udp).get()
					# print 25*'='
					# pp.pprint(ans)
					# print 25*'='
					return ans

				# print 'IPv6 UDP','port:',udp.dport,'src:',self.getip(ip.src,True),'dst:',self.getip(ip.dst,True)

			# TCP not useful
			elif ip.p == dpkt.ip.IP_PROTO_TCP:
				tcp = ip.data
				# print 'IPv6 TCP','port:',tcp.dport,'src:',self.getip(ip.src,True),'dst:',self.getip(ip.dst,True)

			# ICMP error msg not useful for mapping
			elif ip.p == dpkt.ip.IP_PROTO_ICMP6:
				# print 'IPv6 icmp6:',ip.data.data
				0

			# other stuff I haven't decoded
			else:
				0
				# print 'IPv6',ip.p,'src:',self.getip(ip.src,True),'dst:',self.getip(ip.dst,True)
		elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
			ip = eth.data

			# roku interface port: 1900 dst: 239.255.255.250 1900
			if ip.p == dpkt.ip.IP_PROTO_UDP:
				udp = ip.data

				# these aren't useful
				if udp.dport == 53: #DNS
					# return DNS(udp.data)
					return {}

				elif udp.dport == 5353: # mDNS
					# print 'mDNS'
					# print udp
					return mDNS(udp).get()
				elif self.getip(ip.dst) == '239.255.255.250':
					return {}
				else:
					# don't print standard ports
					# 17500 dropbox
					# if not ip.data.dport in [17500]:
					# 	print 'other udp','port:',udp.dport,'src:',self.getip(ip.src),'dst:',self.getip(ip.dst),':  '
					return {}
			elif ip.p == dpkt.ip.IP_PROTO_TCP:
				# src = self.getip(ip.src)
				# if netaddr.IPAddress(src) not in netaddr.IPNetwork("192.168.1.0/24"):
				# 	who = ''
				# 	if src not in self.ipMap:
				# 		who = WhoIs(src).record['NetName']
				# 		self.ipMap[src] = who
				# 	else:
				# 		who = self.ipMap[src]
				# 	if who in ['GOOGLE','AKAMAI','APPLE-WWNET','AMAZO-ZIAD1','DROPBOX']:
				# 		return {}
				# 	else:
				# 		print src,who
				# don't print standard ports
				# port 58969 - XSANS Apple, why do i see that?
				# 22 ssh
				# 25 smtp
				# 80 http
				# 123 time server
				# 143 imap
				# 443 https
				# 445 smb
				# 548 afp over tcp
				# 5009 airport admin utility
				# 5222 ichat
				# 17500 dropbox
				# if not ip.data.dport in [22,25,80,123,143,443,445,548,5009,5222,17500]:
					# print 'other tcp','port:',ip.data.dport,'src:',self.getip(ip.src),'dst:',self.getip(ip.dst)
				return {}
			# elif ip.p == dpkt.ip.IP_PROTO_ICMP6:
			# 	print '?????? other icmp6','src:',self.getip(ip.src),'dst:',self.getip(ip.dst)
			elif ip.p == 2:
				0
				# print 'IGMP','src:',self.getip(ip.src),'dst:',self.getip(ip.dst)
			else:
				# print 'other ip packet','src:',self.getip(ip.src),'dst:',self.getip(ip.dst)
				return {}

####################################################

####################################################

class PassiveMapper(object):
	def __init__(self):
		self.map = []

	def process(self,hrd,data):
		"""
		Processes each packet from pcap
		"""
		eth = dpkt.ethernet.Ethernet (data)

		a = self.p.decode(eth)
		if a: self.map.append(a)

	def pcap(self,fname):
		"""
		opens a pcap file and reads the contents
		"""
		cap = pcapy.open_offline(fname)

		self.map = []
		self.p = PacketDecoder()
		cap.loop(0,self.process)

		return self.map

	def rr(self,rec):
		ans = {'hostname':'','tcp':[], 'udp': []}
		for line in rec['rr']:
			rtype = line['type']
			if rtype == 'ptr': 0
			elif rtype == 'txt': 0
			elif rtype == 'srv':
				ans['hostname'] = line['hostname']
				if line['proto'] == '_tcp': ans['tcp'].append({'srv': line['srv'], 'port': line['port']})
				elif line['proto'] == '_udp': ans['udp'].append({'srv': line['srv'], 'port': line['port']})
				else: print 'something happened', line
			# elif type == 'rr': print 'rr'
			elif rtype == 'aaaa':
				ans['ipv6'] = line['ipv6']
				ans['hostname'] = line['hostname']
				# ans['mac'] = line['mac']
			elif rtype == 'a':
				ans['ipv4'] = line['ipv4']
				ans['hostname'] = line['hostname']
				# ans['mac'] = line['mac']
			else: print 'shit', line

		if not ans['hostname'] and not ans['tcp']: ans = {}
		return ans


	def filter(self,rec):
		"""
		The output from pcap is just a list of records, this condenses/combines
		the info into a network mapping.
		"""
		ans = []
		for line in rec:
			# print 25*'-'
			if 'rr' in line:
				# print 'rr: ',line['rr']
				# print 'mdns'
				a = self.rr(line)

				if a:
					a['type'] = 'rr'
					ans.append(a)
			elif 'type' in line:
				# print line['type']
				rtype = line['type']
				# if type == 'ptr': print 'ptr'
				# elif type == 'txt': print 'txt'
				if rtype == 'aaaa': ans.append(line)
				elif rtype == 'a': ans.append(line)
				elif rtype == 'arp': ans.append(line)
				else: print '<<<<', line, '>>>>>>>'
			else:
				print '******',line,'*******'
		return ans

	def find(self,a,list):
		"""
		find a record for the same host and merges the info. If the host can't
		be found, then it adds a new record for the host.
		"""
		for i in list:
			if 'ipv4' in i and 'ipv4' in a:
				if i['ipv4'] == a['ipv4']:
					i.update(a)
					return
			elif 'ipv6' in i and 'ipv6' in a:
				if i['ipv6'] == a['ipv6']:
					i.update(a)
					return
			elif 'hostname' in i and 'hostname' in a:
				if i['hostname'] == a['hostname']:
					i.update(a)
					return
		list.append(a)
		return

	def combine(self,map):
		"""
		lots to do
		"""
		ans = []
		for host in map:
			self.find(host,ans)
		return ans

	def live(self,dev,loop=500):
		"""
		open device
		Arguments here are:
			device
			snaplen (maximum number of bytes to capture _per_packet_)
			promiscious mode (1 for true), need False for OSX
			timeout (in milliseconds)
		"""
		# check for sudo/root privileges
		if os.geteuid() != 0:
				exit('You need to be root/sudo for real-time ... exiting')

		# real-time
		cap = pcapy.open_live(dev , 2048 ,False, 50)
		#cap.setfilter('udp')

		self.map = []
		self.p = PacketDecoder()

		#start sniffing packets
		while(loop):
			try:
				loop -= 1
				(header, data) = cap.next()
			except KeyboardInterrupt:
				print 'You hit ^C, exiting PassiveMapper ... bye'
				exit()
			except:
				continue

			self.process(header,data)

		return self.map

########################################################


def handleArgs():
	description = """The passive mapper primarily listens and records mDNS
	traffic.
	Example:
		pscan --file network.pcap --save network.json

	"""
	parser = argparse.ArgumentParser(description)
	args = parser.parse_args()
	return args

def main():
	args = handleArgs()

	map = []
	pm = PassiveMapper()
	map = pm.pcap('test.pcap')
	map = pm.filter(map)
	map = pm.combine(map)
	map = pm.combine(map)
	pp.pprint( map )

	return map



if __name__ == "__main__":
	main()

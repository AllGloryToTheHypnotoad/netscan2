#!/usr/bin/env python

import datetime     # time stamp
import pcapy	    # passive mapping
import os		    # check sudo
import time         # sleep on loop
import dpkt		    # parse packets
import binascii     # get MAC addr on ARP messages
import netaddr	    # ipv4/6 addresses, address space: 192.168.5.0/24
import json		    # store hosts
import pprint as pp # display info
import commands     # arp-scan
import requests     # mac api
import argparse     # command line arguments
import socket       # ordering
import sys          # get platform (linux or linux2)
from awake import wol # wake on lan

"""
[kevin@Tardis test]$ ./pmap5.py -p test2.pcap -d
Reading pcap file: test2.pcap
[{'hostname': 'Dalek.local',
  'ipv4': '192.168.1.13',
  'ipv6': 'fe80::ca2a:14ff:fe1f:1869',
  'mac': 'c8:2a:14:1f:18:69',
  'os': '',
  'tcp': [],
  'udp': []},
 {'hostname': 'Kids-iPod-touch.local',
  'ipv4': '192.168.1.21',
  'ipv6': 'fe80::105b:fc94:62aa:1da7',
  'tcp': [],
  'udp': []},
 {'hostname': 'calculon.local',
  'ipv4': '192.168.1.17',
  'mac': 'b8:27:eb:0a:5a:17',
  'os': '',
  'tcp': [],
  'udp': []},
 {'hostname': 'bender.local',
  'ipv4': '192.168.1.18',
  'mac': 'b8:27:eb:8f:23:20',
  'os': '',
  'tcp': [],
  'udp': []},
 {'hostname': 'AirportExtreme.local',
  'ipv4': '192.168.1.1',
  'ipv6': 'fe80::6e70:9fff:fece:da85',
  'mac': '6c:70:9f:ce:da:85',
  'os': '',
  'tcp': [{5009: 'acp-sync'}, {5009: 'airport'}],
  'udp': [{59086: 'sleep-proxy'}]},
 {'hostname': 'Office-Apple-TV.local',
  'ipv4': '192.168.1.14',
  'ipv6': 'fe80::4c3:f29f:823f:4eca',
  'tcp': [{7000: 'airplay'},
          {5000: 'raop'},
          {3689: 'touch-able'},
          {3689: 'appletv-v2'}],
  'udp': []},
 {'hostname': 'Apple-TV.local',
  'ipv4': '192.168.1.15',
  'ipv6': 'fe80::18b5:5727:6dbe:d109',
  'tcp': [],
  'udp': []},
 {'hostname': 'unknown',
  'ipv4': '192.168.1.4',
  'mac': 'f8:1e:df:ea:68:20',
  'os': u'Apple'}]
  



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
	   -- icnmpv6:
	"""
	def add_colons_to_mac(self, mac_addr) :
		"""
		This function accepts a 12 hex digit string and converts it to a colon
		separated string
		"""
		s = list()
		for i in range(12/2) :	# mac_addr should always be 12 chars, we work in groups of 2 chars
			s.append( mac_addr[i*2:i*2+2] )
		r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
		return r
		
	def decode(self,eth):
		"""
		decode an ethernet packet. The dict returned indicates the type (arp,mdns,etc) 
		which will indicate how to read/use the dict.
		
		in: ethernet pkt
		out: dict
		"""
		if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
			arp = eth.data
			if arp.op == dpkt.arp.ARP_OP_REPLY:
				msg={'type':'arp', 'mac': self.add_colons_to_mac( binascii.hexlify(arp.sha) ),'ipv4':socket.inet_ntoa(arp.spa)}
				return msg
			else: return {}
		#elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
		elif eth.type == dpkt.ethernet.ETH_TYPE_IP:			
			ip = eth.data
			if ip.p == dpkt.ip.IP_PROTO_UDP:
				udp = ip.data

# 				if udp.dport == 53: #DNS
# 					dns = dpkt.dns.DNS(udp.data)
# 					for rr in dns.an:
# 						h = self.getRecord(rr)
# 						print h
						
				if udp.dport == 5353: # mDNS
					msg = {}					
					try:
						mdns = dpkt.dns.DNS(udp.data)	 
					except dpkt.Error:	
						#print 'dpkt.Error' 
						return msg
					except (IndexError, TypeError):
						# dpkt shouldn't do this, but it does in some cases
						#print 'other error'
						return msg
	
					if mdns.qr != dpkt.dns.DNS_R: return msg
					if mdns.opcode != dpkt.dns.DNS_QUERY: return msg
					if mdns.rcode != dpkt.dns.DNS_RCODE_NOERR: return msg
					
					msg['type'] = 'mdns'
					ans = []

					for rr in mdns.an:
						h = self.getRecord(rr)
						
						# check if empty
						if h: ans.append( h )
						
					msg['rr'] = ans
					return msg
				else: return {}
			else: return {}
		
	def getRecord(self,rr):
		"""
		The response records (rr) in a dns packet all refer to the same host
		"""
		if   rr.type == 1:  return {'type': 'a', 'ipv4': socket.inet_ntoa(rr.rdata),'hostname': rr.name}
		elif rr.type == 28: return {'type': 'aaaa', 'ipv6': socket.inet_ntop(socket.AF_INET6, rr.rdata), 'hostname': rr.name}
		elif rr.type == 5:  return {'type': 'cname', 'hostname': rr.name, 'cname': rr.cname}
		elif rr.type == 13: return {'type': 'hostinfo', 'hostname': rr.name, 'info': rr.rdata}
		elif rr.type == 33: return {'type': 'srv', 'hostname': rr.srvname, 'port': rr.port, 'srv': rr.name.split('.')[-3], 'proto': rr.name.split('.')[-2]} 
		elif rr.type == 12: return {'type': 'ptr'} 
		elif rr.type == 16: return {'type': 'txt'}  
		elif rr.type == 10: return {'type': 'wtf'}	

#########################

def macLookup(mac):
	"""
	json responce from www.macvendorlookup.com:
	
	{u'addressL1': u'1 Infinite Loop',
	u'addressL2': u'',
	u'addressL3': u'Cupertino CA 95014',
	u'company': u'Apple',
	u'country': u'UNITED STATES',
	u'endDec': u'202412195315711',
	u'endHex': u'B817C2FFFFFF',
	u'startDec': u'202412178538496',
	u'startHex': u'B817C2000000',
	u'type': u'MA-L'}
	"""
	try:
		r = requests.get('http://www.macvendorlookup.com/api/v2/' + mac)
	except requests.exceptions.HTTPError as e:
		print "HTTPError:", e.message
		return {'company':'unknown'}
	
	if r.status_code == 204: # no content found, bad MAC addr
		print 'ERROR: Bad MAC addr:',mac
		return {'company':'unknown'}
	elif r.headers['content-type'] != 'application/json':
		print 'ERROR: Wrong content type:', r.headers['content-type']
		return {'company':'unknown'}
	a={}
	
	try:
		a = r.json()[0]
		#print 'GOOD:',r.status_code,r.headers,r.ok,r.text,r.reason
	except:
		print 'ERROR:',r.status_code,r.headers,r.ok,r.text,r.reason
		a = {'company':'unknown'}
	
	return a
	




####################################################

class ArpScan(object):
	def scan(self,dev):
		"""
		brew install arp-scan
	
		arp-scan -l -I en1
		 -l use local networking info
		 -I use a specific interface
	 
		 return {mac: ip}
		 
		 Need to invest the time to do this myself w/o using commandline
		"""
		arp = commands.getoutput("arp-scan -l -I %s"%(dev))
		a = arp.split('\n')
		ln = len(a)
	
		d = []
		for i in range(2,ln-3):
			b = a[i].split()
			d.append( {'type':'arp', 'mac': b[1],'ipv4': b[0]} )
	
		return d

class Analyzer(object):

	def getHostName(self,ip):
		"""Use the avahi (zeroconfig) tools to find a host name ... this only works
		on Linux using the avahi tools.

		in: ip
		out: string w/ host name
		"""
		name = 'unknown'
		if sys.platform == 'linux' or sys.platform == 'linux2':
			cmd = ["avahi-resolve-address %s | awk '{print $2}'"%(ip)]
			#name  = self.runProcess(cmd)
			name = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]
			name = name.rstrip()
			if name == '': name = 'unknown'
		return name
	
	def find(self,net,ip):
		"""
		finds a recored in a list
		"""
		return next(x for x in net if x['ipv4'] == ip)
# 		
# 		print 'find:',ip
# 		for r in net:
# 			print r['ipv4'] 
# 			if r['ipv4'] == ip: return r
				
	def check(self,net,rec):
		"""
		check if an ipv4 host record already exists
		"""
		for r in net:
			if r['ipv4'] == rec['ipv4']: return True
		return False
	
# 	def checkSrv(self,ar,svc):
# 		"""
# 		check if a service record already exists
# 		"""
# 		for s in ar:
# 			if s == svc: return True
# 		return False	
		
	def merge(self,map,active):
		"""
		Merges the active and passive scans
		
		map - records found during passive mapping
		active - active scan results
		
		*---
		  AAAA: fe80::ca2a:14ff:fe1f:1869 is Dalek.local
		*---
		  A: 192.168.1.13 is Dalek.local
		*---
		  ARP: 192.168.1.13 is c8:2a:14:1f:18:69
		*---
		  TXT: 192.168.1.19 _device-info[_tcp] type: 16
		*---
		"""
		
		for i in active:
			map.append(i)
		
		net = []
		
		# go thru everything passively collected and build a network map
		for i in map:
			# mdns are the primary good ones
			if i['type'] == 'mdns':
				rec={'tcp':[],'udp':[]}
				ar = i['rr']
				
				# for each mdns record type: a, aaaa, srv, ...
				for rr in ar:
					if rr['type'] == 'a': 
						rec['ipv4'] = rr['ipv4']
						rec['hostname'] = rr['hostname'] 
					elif rr['type'] == 'aaaa': rec['ipv6'] = rr['ipv6'] 
					elif rr['type'] == 'srv':
						srv = ( rr['port'], rr['srv'][1:] )
						if rr['proto'] == '_tcp': 
							rec['tcp'].append(srv)
						elif rr['proto'] == '_udp': 
							rec['udp'].append(srv)
				
				# see if mdns has already been found
				if 'ipv4' in rec:
					if not self.check(net,rec): net.append(rec)
		
		# arp is the other most useful passively collected, go through and find hosts
		# not found in the passive mapping or update hosts with other info (mac, ports, etc)
		
		# start with arp to get all hosts found
		for i in map:	
			if i['type'] == 'arp':
				found = False
				# see if the ip has been found, if so, add the mac addr
				for host in net:
					if i['ipv4'] == host['ipv4']:
						host['mac'] = i['mac']
						host['os'] = macLookup(i['mac'])['company']
						found = True
				# if not found, then add a new host record
				if not found:
					net.append({'ipv4': i['ipv4'], 'mac': i['mac'], 'os': macLookup(i['mac'])['company']})
		
		# now do ports after all hosts found
		for i in map:	
			if i['type'] == 'portscan':
# 				print 'portscan',i['ipv4'],i['ports']
				host = self.find(net,i['ipv4'])
				if 'tcp' not in host:
					host['tcp'] = i['ports']
				else:
					host['tcp'] = list(set( i['ports'] + host['tcp'] )) # combine port arrays
				
				if 'udp' not in host:
					host['udp'] = []

						
			
		# go through everything and add some other info
		for i in net:	
			if 'hostname' not in i: i['hostname'] = self.getHostName( i['ipv4'] )
			if 'mac' in i and 'os' not in i: i['os'] = macLookup(i['mac'])['company']
			
			i['lastseen'] = str(datetime.datetime.now().strftime('%H:%M %a %d %b %Y'))
			i['status'] = 'up'
			
			if 'tcp' in i and i['tcp']: i['tcp'] = list(set( i['tcp'] )) 
			if 'udp' in i and i['udp']: i['udp'] = list(set( i['udp'] ))
		
		return net

####################################################	

class PassiveMapper(object):
	def __init__(self):
		self.map = []
		
	def process(self,hrd,data):
		eth = dpkt.ethernet.Ethernet (data)
	
		a = self.p.decode(eth)
		if a: self.map.append(a)

	def pcap(self,file):
		"""
		opens a pcap file and reads the contents
		"""
		cap = pcapy.open_offline(file)
	
		self.map = []
		self.p = PacketDecoder()	
		cap.loop(0,self.process)
	
		return self.map

	def live(self,dev,loop=500):
		"""
		open device
		# Arguments here are:
		#	device
		#	snaplen (maximum number of bytes to capture _per_packet_)
		#	promiscious mode (1 for true), need False for OSX
		#	timeout (in milliseconds)
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


class IP:
	"""Gets the IP and MAC addresses for the localhost"""
	ip = 'x'
	mac = 'x'

	def __init__(self):
		"""Everything is done in init(), don't call any methods, just access ip or mac."""
		self.mac = self.getHostMAC()
		self.ip = self.getHostIP()

	def getHostIP(self):
		"""
		Need to get the localhost IP address
		in: none
		out: returns the host machine's IP address
		"""
		host_name = socket.gethostname()
		if '.local' not in host_name: host_name = host_name + '.local'
		ip = socket.gethostbyname(host_name)
		return ip

	def getHostMAC(self,dev='en1'):
		"""
		Major flaw of NMAP doesn't allow you to get the localhost's MAC address, so this 
		is a work around.
		in: none
		out: string of hex for MAC address 'aa:bb:11:22..' or empty string if error
		"""
		# this doesn't work, could return any network address (en0, en1, bluetooth, etc)
		#return	':'.join(re.findall('..', '%012x' % uuid.getnode()))
		mac = commands.getoutput("ifconfig " + dev + "| grep ether | awk '{ print $2 }'")
		
		# double check it is a valid mac address
		if len(mac) == 17 and len(mac.split(':')) == 6: return mac
		
		# nothing found
		return ''

class Pinger(object):
	"""
	Determine if host is up. 
	
	ArpScan is probably better ... get MAC info from it
	"""
	def __init__(self):
		comp = IP()
		self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_ICMP)
		self.sniffer.bind((comp.ip,1))
		self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		self.sniffer.settimeout(1)
		
		self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	def createICMP(self,msg):
		echo = dpkt.icmp.ICMP.Echo()
		echo.id = random.randint(0, 0xffff)
		echo.seq = random.randint(0, 0xffff)
		echo.data = msg

		icmp = dpkt.icmp.ICMP()
		icmp.type = dpkt.icmp.ICMP_ECHO
		icmp.data = echo
		return str(icmp)
	
	def ping(self,ip):
		#print 'Ping',ip
		try:
			msg = self.createICMP('test')
			self.udp.sendto(msg,(ip, 10))
		except socket.error as e:
			print e,'ip:',ip
			
		try:
			self.sniffer.settimeout(0.01)
			raw_buffer = self.sniffer.recvfrom(65565)[0]
		except socket.timeout:
			return ''
		
		return raw_buffer
	
	def scanNetwork(self,subnet):
		"""
		For our scanner, we are looking for a type value of 3 and a code value of 3, which 
		are the Destination Unreachable class and Port Unreachable errors in ICMP messages.
		"""
		net = {}
	
		# continually read in packets and parse their information
		for ip in na.IPNetwork(subnet).iter_hosts():
			raw_buffer = self.ping(str(ip))
		
			if not raw_buffer:
				continue
			
			ip = dpkt.ip.IP(raw_buffer)
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			icmp = ip.data
		
			# ICMP_UNREACH = 3
			# ICMP_UNREACH_PORT = 3
			# type 3 (unreachable) code 3 (destination port)
			# type 5 (redirect) code 1 (host) - router does this
			if icmp.type == dpkt.icmp.ICMP_UNREACH and icmp.code == dpkt.icmp.ICMP_UNREACH_PORT:
				net[src] = 'up'
		
		return net



class PortScanner(object):
 	def __init__(self,ports=range(1,1024)):
 		self.ports = ports
 		
 	def getBanner(self,ip,port):
 		return ''
		
	def openPort(self,ip,port):
		try:			
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(0.01)
			self.sock.connect((ip, port))
			return True
		except KeyboardInterrupt:
			print "You pressed Ctrl+C, killing PortScanner"
			exit()	
		except:
			self.sock.close()
			return False
			
	def scan(self,ip,banner=False):
 		tcp = []
 		
		for port in self.ports:	
			good = self.openPort(ip,port)
			if good:
				svc = socket.getservbyport(port).strip()
				tcp.append( (port,svc) )
# 			if banner and good:
# 				ports[str(port)+'_banner'] = self.getBanner(ip,port)
		
		self.sock.close()
		return tcp

class ActiveMapper(object):
	"""
	
	"""
	def __init__(self,ports=range(1,1024)):
		self.ps = PortScanner(ports)
		self.asn = ArpScan()
		
	def wol(self, mac):
		"""
		Wake-on-lan (wol)
		in: hw addr
		out: None
		"""
		wol.send_magic_packet(mac)
			
	def scan(self,dev):
		"""
		arpscan - {'type':'arp', 'mac': b[1],'ipv4': b[0]}
		portscan - [ (svc,port) ]
		activescan - {'type': 'portscan', 'ipv4': ip, 'ports': [portscan]}
		"""
		arp = self.asn.scan(dev)
		
		ports = []
		for host in arp:
			#print host
			p = self.ps.scan( host['ipv4'] )
			if p: ports.append( {'type': 'portscan', 'ipv4': host['ipv4'], 'ports':p} )
			
		for i in arp:
			ports.append(i)
			
		return ports


########################################################
		
def main():
	
	print('Hello and goodbye!')
		
 
if __name__ == "__main__":
  main()

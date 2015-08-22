#!/usr/bin/python

import datetime # time stamp
import socket   # sort ip addresses in order

class WebPage:
	"""
	Creates a simple webpage from a json/dict
	"""
	def __init__(self):
		self.page = []
		self.table = ''
	
	def search(self,ip,info):
		"""
		used in conjunction w/ sort_ip(), once a list of sorted ip's is produced, then
		this function is used to help pull them out of the list.
		"""
		for host in info:
			if ip == host['ipv4']:
				return host
		raise Exception('Error: search() should not have gotten here')
	
	def sort_ip(self,info):
		"""
		Using a function in socket, sorts the IP address in order.
		"""
		ip = []
		for host in info:
			ip.append( host['ipv4'] )
		ip_sorted = sorted(ip, key=lambda item: socket.inet_aton(item))
		return ip_sorted
		
	# Note: this auto refreshes every 300 seconds.
	def create(self):
		"""
		Creates a simple webpage. 
		"""
		html_start = """
		<!DOCTYPE html>
		<html>
		  <head>
			<title>html5</title>
			<meta charset="utf-8">
			<!--link rel="stylesheet" href="http://yui.yahooapis.com/pure/0.6.0/pure-min.css"-->
			<link rel="stylesheet" href="http://yui.yahooapis.com/pure/0.6.0/tables-min.css">
		  </head>
		  <body>
		"""
		
		html_end = """	
		  </body>
		</html>
		"""
		
		page = []
		page.append(html_start)
		page.append(self.table)
		page.append(html_end)
		
		self.page = page
	
	def savePage(self,filename):
		"""
		Saves page to file
		"""
		f = open(filename,'w')
		for i in self.page:
			f.write(i)
		f.close()
	
	def makePorts(self,tcp,udp):
		"""
		makes a sub-table for the open ports
		"""
		p = ['<td><table  class="pure-table pure-table-horizontal">']
		
		if tcp: 
			p.append('<tr><thead><th> TCP </th><th>  </th></thead></tr>')
			p.append('<tbody>')
			for i in tcp: p.append('<tr><td> %d </td><td> %s </td></tr>'%(i[0],i[1]) )
			p.append('</tbody>')
		if udp: 
			p.append('<tr><thead><th> UDP </th><th>  </th></thead></tr>')
			p.append('<tbody>')
			for i in udp: p.append('<tr><td> %d </td><td> %s </td></tr>'%(i[0],i[1]) )
			p.append('</tbody>')
		p.append('</table></td>')
		
		#print ''.join(p)
		
		return ''.join(p)
		
		
	def makeRow(self,header,host):
		"""
		makes a row
		
		in: header - the key for each column
		    host - json/dict for a single host containing the key/value pair for each column
		"""
		row = []
		row.append('<tr>')
		for head in header:
			if head == 'hostname': row.append('<td> %s </td>'%(host[head].rstrip('.local')))
			elif head == 'ports': 
				if 'tcp' in host or 'udp' in host: row.append( self.makePorts(host['tcp'],host['udp']) )
				else: row.append('<td>  </td>')
			elif head in host: row.append('<td> %s </td>'%(host[head]))
			else: row.append('<td>  </td>')
		row.append('</tr>')
		
		return ''.join( row )
		
	
	def setInfo(self,header,info):
		"""
		creates the table
		
		in: header - list of each key for each column
		    info - a list of each host's info
		"""
		
		table = []
		
		table.append('<h1>Network Scan </h1><h3>Last Updated: %s</h3>'%(str(datetime.datetime.now().strftime('%H:%M %d-%m-%Y'))))
		
		#table.append('<style> table, tr, th { border: 1px solid gray; border-collapse: collapse;} th {background-color: #0066FF; color: white;} #porttable, #porttd { border: 0px;}</style>')
	
		table.append('<table class="pure-table pure-table-bordered">')
		
		# Make table header
		table.append('<thead><tr>')
		for head in header:
			table.append('<th> %s </th>'%(head))
		table.append('</tr></thead>')
		
		sorted_info = self.sort_ip(info)
		#print sorted_info
		
		table.append('<tbody>')
		for ip in sorted_info:
			table.append( self.makeRow(header, self.search(ip,info) ) )
		table.append('</tbody>')
		
		table.append('</table>')
		self.table = ''.join(table)
		
	# Expect a list containing lines of html which will create a Google Map	
	def printPage(self):
		"""
		Prints page to screen
		"""
		for i in self.page:
			print i


def main():
	page = WebPage()
	
# 	header = ['ipv4','hostname','mac','os','ports','ipv6','status','lastseen']
	header = ['ipv4','hostname','mac','os','ports','ipv6']
	network = [{'hostname': 'Dalek.local',
  'ipv4': '192.168.1.13',
  'ipv6': 'fe80::ca2a:14ff:fe1f:1869',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': 'c8:2a:14:1f:18:69',
  'os': u'Apple',
  'status': 'up',
  'tcp': [(88, 'kerberos'), (22, 'ssh')],
  'udp': []},
 {'hostname': 'Kids-iPod-touch.local',
  'ipv4': '192.168.1.21',
  'ipv6': 'fe80::105b:fc94:62aa:1da7',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'status': 'up',
  'tcp': [],
  'udp': []},
 {'hostname': 'calculon.local',
  'ipv4': '192.168.1.17',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': 'b8:27:eb:0a:5a:17',
  'os': u'Raspberry Pi Foundation',
  'status': 'up',
  'tcp': [(22, 'ssh')],
  'udp': []},
 {'hostname': 'bender.local',
  'ipv4': '192.168.1.18',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': 'b8:27:eb:8f:23:20',
  'os': u'Raspberry Pi Foundation',
  'status': 'up',
  'tcp': [(22, 'ssh')],
  'udp': []},
 {'hostname': 'AirportExtreme.local',
  'ipv4': '192.168.1.1',
  'ipv6': 'fe80::6e70:9fff:fece:da85',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': '6c:70:9f:ce:da:85',
  'os': u'Apple',
  'status': 'up',
  'tcp': [(5009, 'airport'), (5009, 'acp-sync'), (53, 'domain')],
  'udp': [(59086, 'sleep-proxy')]},
 {'hostname': 'Office-Apple-TV.local',
  'ipv4': '192.168.1.14',
  'ipv6': 'fe80::4c3:f29f:823f:4eca',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'status': 'up',
  'tcp': [(3689, 'appletv-v2'),
          (7000, 'airplay'),
          (5000, 'raop'),
          (3689, 'touch-able')],
  'udp': []},
  {'hostname': 'unknown',
  'ipv4': '192.168.1.23',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': '28:0d:fc:41:24:44',
  'os': u'Sony Computer Entertainment Inc.',
  'status': 'up'},
 {'hostname': 'unknown',
  'ipv4': '192.168.1.20',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': 'a8:e3:ee:bd:20:ae',
  'os': u'Sony Computer Entertainment Inc.',
  'status': 'up'},
 {'hostname': 'unknown',
  'ipv4': '192.168.1.26',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': '68:d9:3c:4b:35:a8',
  'os': u'Apple',
  'status': 'up'},
 {'hostname': 'unknown',
  'ipv4': '192.168.1.90',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': '00:21:5a:fe:bc:4a',
  'os': u'Hewlett-Packard Company',
  'status': 'up'},
 {'hostname': 'unknown',
  'ipv4': '192.168.1.137',
  'lastseen': '11:17 Sat 04 Jul 2015',
  'mac': '5c:95:ae:93:2f:a5',
  'os': u'Apple',
  'status': 'up'}]
  
	page.setInfo(header,network)
	page.create()
	page.savePage('test.html')
	

if __name__ == "__main__":
	main()
#!/usr/bin/env python

import datetime # time stamp
import socket	# sort ip addresses in order
import sys		# command line args
import json		# read netscan files

class WebPage(object):
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
			p.append('<tr><thead><th> TCP </th><th>	 </th></thead></tr>')
			p.append('<tbody>')
			for i in tcp: p.append('<tr><td> %d </td><td> %s </td></tr>'%(i[0],i[1]) )
			p.append('</tbody>')
		if udp: 
			p.append('<tr><thead><th> UDP </th><th>	 </th></thead></tr>')
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
				else: row.append('<td>	</td>')
			elif head in host: row.append('<td> %s </td>'%(host[head]))
			else: row.append('<td>	</td>')
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
	
	if len(sys.argv) < 2:
		print('Error, must give a json file name: html5 network.json\nUse a netscan json file')
		exit(1)
		
	page = WebPage()
	
#	header = ['ipv4','hostname','mac','os','ports','ipv6','status','lastseen']
	header = ['ipv4','hostname','mac','os','ports','ipv6']
	network = {}
	with open(sys.argv[1]) as data_file:	
		network = json.load(data_file)
	
	page.setInfo(header,network)
	page.create()
	page.savePage('test.html')
	

if __name__ == "__main__":
	main()
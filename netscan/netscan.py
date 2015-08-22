#!/usr/bin/env python

import netlib as nl # all the classes to get things done
import pprint as pp # debug
import html5        # make webpage
import argparse     # handle command line


def handleArgs():
	description = """A simple active/passive network recon program. It conducts an arp 
	ping to get MAC addresses and IPv4 addresses. An active part then uses the ip addresses
	to scan for open ports. The remainder of the information is passively obtained using 
	the pcap library.
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('-w', '--webpage', help='name of webpage', default='./network.html')
	parser.add_argument('-c', '--pcap', help='pcap file name', default='')
	parser.add_argument('-a', '--activeonly', help='no passive, active only', action='store_true', default=False)
	parser.add_argument('-p', '--passiveonly', help='no active, passive only', action='store_true', default=False)
# 	parser.add_argument('-n', '--network', help='network: 10.1.1.0/24 or 10.1.1.1-10', default='192.168.1.0/24')
	parser.add_argument('-y', '--yaml', help='yaml file to store network in', default='./network.yaml')
	parser.add_argument('-i', '--interface', help='network interface to use', default='')
	parser.add_argument('-d', '--display', help='print to screen', action='store_true', default=False)
	parser.add_argument('-s', '--scan', help='number of packets to get before reporting, only applicable to live scan not off-line pcap', default=1000)
	parser.add_argument('-r', '--range', help='range of active port scan: 1..n', default='1024')
	args = vars(parser.parse_args())

	return args

def main():
	# handle inputs
	args = handleArgs()
# 	network = args['network']
	dev = args['interface']
	pcapFile = args['pcap']
	pkts = int(args['scan'])
	prnt = args['display']
	webpage = args['webpage']
	maxport = int(args['range'])
	active_only = args['activeonly']
	passive_only = args['passiveonly']
	
	# start loop here ---
	passive_scan = []
	active_scan = []
	
	# start passive scan, live or reading pcap
	if not active_only:
		print 'Start passive'
		pm = nl.PassiveMapper()
		if pcapFile: 
			# how was pcap generated???
			print 'Reading pcap file:', pcapFile
			passive_scan = pm.pcap(pcapFile)
		elif dev:
			passive_scan = pm.live(dev,pkts)
		else:
			print 'Need to give interface (-i en1) or pcap file (-p myfile.pcap)'
			exit()
		print 'End passive'
	
	# active only does port scan and arp scan (mac/ip) right now
	# - mdns search
	# - ipv6 host search
	# - need to write arp search instead of using command line tool
	# - fix issue of active port scan not getting into webpage results (portscan)
	if not passive_only:
		print 'Start active scan'
		am = nl.ActiveMapper(range(1,maxport)) 
		active_scan = am.scan()
		#pp.pprint( active_scan )
	
	# merge together active and passive scans
	an = nl.Analyzer()

	print 'Merge results'
	net = an.merge(passive_scan,active_scan)
	
	if prnt: pp.pprint( net )
	
	# save to yaml
	
	# make html
	print 'Save webpage'
	page = html5.WebPage()
	header = ['ipv4','hostname','mac','os','ports','ipv6','lastseen']
	page.setInfo(header,net)
	page.create()
	page.savePage(webpage)
	
	# end loop here ---

if __name__ == "__main__":
  main()
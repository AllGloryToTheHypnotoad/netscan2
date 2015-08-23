#!/usr/bin/env python

import netlib as nl # all the classes to get things done
import pprint as pp # debug
import html5        # make webpage
import argparse     # handle command line
import json         # save data
import os           # determine sudo


def handleArgs():
	description = """A simple active/passive network recon program. It conducts an arp 
	ping to get MAC addresses and IPv4 addresses. An active part then uses the ip addresses
	to scan for open ports. The remainder of the information is passively obtained using 
	the pcap library.
	
	examples:
	
		sudo netscan -a -i en1 -r 5000
		sudo netscan -p 1000 -i en1 
		sudo netscan -a -p 500 -i en1 -j network.json
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('-j', '--json', help='name of json file', default='')
	parser.add_argument('-w', '--webpage', help='name of webpage', default='')
# 	parser.add_argument('-c', '--pcap', help='pcap file name', default='')
	parser.add_argument('-a', '--active', help='scan active', action='store_true', default=False)
	parser.add_argument('-p', '--passive', help='scan passive, how many packets to look for', default=0)
# 	parser.add_argument('-n', '--network', help='network: 10.1.1.0/24 or 10.1.1.1-10', default='192.168.1.0/24')
# 	parser.add_argument('-y', '--yaml', help='yaml file to store network in', default='./network.yaml')
	parser.add_argument('-i', '--interface', help='network interface to use', default='')
# 	parser.add_argument('-d', '--display', help='print to screen', action='store_true', default=False)
# 	parser.add_argument('-s', '--scan', help='number of packets to get before reporting, only applicable to live scan not off-line pcap', default=1000)
	parser.add_argument('-r', '--range', help='range of active port scan: 1..n', default='1024')
	args = vars(parser.parse_args())

	return args

def main():
	# handle inputs
	args = handleArgs()
# 	network = args['network']
	dev = args['interface']
	if not dev: 
		exit('Error: you MUST give an interface to scan or list on, ex. -i en1')
		
	if os.geteuid() != 0:
		exit('You need to be root/sudo for this ... exiting')
	
# 	pcapFile = args['pcap']
	pkts = int(args['passive'])
# 	prnt = args['display']
	webpage = args['webpage']
	maxport = int(args['range'])
	active = args['active']
	passive = True if pkts > 0 else False
	json_file = args['json']
	
	# start loop here ---
	passive_scan = []
	active_scan = []
	
	# start passive scan, live or reading pcap
	if passive:
		print 'Start passive'
		pm = nl.PassiveMapper()
# 		if pcapFile: 
# 			# how was pcap generated???
# 			print 'Reading pcap file:', pcapFile
# 			passive_scan = pm.pcap(pcapFile)
# 		elif dev:
# 			passive_scan = pm.live(dev,pkts)
# 		else:
# 			print 'Need to give interface (-i en1) or pcap file (-p myfile.pcap)'
# 			exit()
		passive_scan = pm.live(dev,pkts)
		print 'End passive'
	
	# active only does port scan and arp scan (mac/ip) right now
	# - mdns search
	# - ipv6 host search
	# - need to write arp search instead of using command line tool
	# - fix issue of active port scan not getting into webpage results (portscan)
	if active:
		print 'Start active scan'
		am = nl.ActiveMapper(range(1,maxport)) 
		active_scan = am.scan(dev)
		#pp.pprint( active_scan )
	
	# merge together active and passive scans
	an = nl.Analyzer()

	print 'Merge results'
	net = an.merge(passive_scan,active_scan)
	
# 	if prnt: pp.pprint( net )
	
	# handle output
	if json_file:
		with open(json_file, 'w') as fp:
			json.dump(net, fp)

	elif webpage:
		# make html
		print 'Save webpage'
		page = html5.WebPage()
		header = ['ipv4','hostname','mac','os','ports','ipv6','lastseen']
		page.setInfo(header,net)
		page.create()
		page.savePage(webpage)
	
	else:
		pp.pprint( net )
	
	# end loop here ---

if __name__ == "__main__":
  main()
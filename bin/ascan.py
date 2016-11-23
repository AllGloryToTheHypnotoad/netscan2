#!/usr/bin/env python

import os
import sys
import simplejson as json
import argparse
import pprint as pp  # display info
from netscan.ActiveScan import ActiveMapper


def handleArgs():
	description = """A simple active network recon program. It conducts an arp
	ping to get MAC addresses and IPv4 addresses. Avahi or dig are used to get host
	names. It also scans for open ports on each host. The information is printed to the
	screen, saved to a json file, or sent to another computer

	examples:

		sudo netscan -i en1 -s network.json -r 5000
		sudo netscan -j http://localhost:9000/json
	"""
	parser = argparse.ArgumentParser(description)
	# parser.add_argument('-j', '--json', help='name of json file', default='')
	# parser.add_argument('-w', '--webpage', help='name of webpage', default='')
	# parser.add_argument('-c', '--pcap', help='pcap file name', default='')
	# parser.add_argument('-a', '--active', help='scan active', action='store_true', default=False)
	# parser.add_argument('-p', '--passive', help='scan passive, how many packets to look for', default=0)
	# parser.add_argument('-n', '--network', help='network: 10.1.1.0/24 or 10.1.1.1-10', default='192.168.1.0/24')
	# parser.add_argument('-y', '--yaml', help='yaml file to store network in', default='./network.yaml')
	parser.add_argument('-i', '--interface', help='network interface to use', default='en1')
	# parser.add_argument('-d', '--display', help='print to screen', action='store_true', default=False)
	parser.add_argument('-s', '--save', help='save output to a file', default='')
	parser.add_argument('-r', '--range', help='range of active port scan: 1..n', default='1024')
	args = vars(parser.parse_args())

	return args


def main():
	# handle inputs
	args = handleArgs()

	# check for sudo/root privileges
	if os.geteuid() != 0:
		exit('You need to be root/sudo ... exiting')

	try:
		am = ActiveMapper(range(1, int(args['range'])))
		hosts = am.scan(args['interface'])
		pp.pprint(hosts)

		# save file
		if args['save']:
			with open(args['save'], 'w') as fp:
				json.dump(hosts, fp)

		return hosts
	except KeyboardInterrupt:
		exit('You hit ^C, exiting PassiveMapper ... bye')
	except:
		print "Unexpected error:", sys.exc_info()
		exit('bye ... ')


if __name__ == "__main__":
	main()

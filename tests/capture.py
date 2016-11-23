#!/usr/bin/env python

from netscan.lib import CapturePackets
import argparse


def handleArgs():
	description = """
	Grabs packets from an interface (default: en1) and writes them to a file
	(default: network.pcap).
	example:

		capture -s filename -i iface -f 'tcp'
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('-i', '--interface', help='network interface to use', default='en1')
	parser.add_argument('-f', '--filter', help='filters to pass to libpcap', default='')
	#	 parser.add_argument('-d', '--display', help='print to screen', action='store_true', default=False)
	parser.add_argument('-s', '--save', help='save output to a file', default='network.pcap')
	args = vars(parser.parse_args())
	return args

def main():
	# handle inputs
	args = handleArgs()

	# check for sudo/root privileges ??
	if os.geteuid() != 0:
		exit('You need to be root/sudo ... exiting')

	try:
		CapturePackets(args['interface'],args['save'],args['filter'])
	except KeyboardInterrupt:
		exit('You hit ^C, exiting ... bye')
	# except:
	#	 print "Unexpected error:", sys.exc_info()
	#	 exit('bye ... ')


if __name__ == "__main__":
	main()

#!/usr/bin/env python

import pcapy
import os
import sys

class CapturePackets(object):
    """
    todo
    """
    def __init__(self,iface,filename='test.pcap',filter='',num_packets=300):
        # list all the network devices
        #print pcapy.findalldevs()

        max_bytes = 1024
        promiscuous = False
        read_timeout = 100 # in milliseconds
        pc = pcapy.open_live(iface, max_bytes, promiscuous, read_timeout)
        if filter: pc.setfilter(filter)
        self.dumper = pc.dump_open(filename)
        pc.loop(num_packets, self.recv_pkts) # capture packets

    # callback for received packets
    def recv_pkts(self,hdr, data):
        try:
            # print data
            self.dumper.dump(hdr, data)
        except KeyboardInterrupt: # probably show throw error instead
            exit('keyboard exit')
        except:
            exit('crap ... something went wrong')

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
    # 	parser.add_argument('-d', '--display', help='print to screen', action='store_true', default=False)
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
	# 	print "Unexpected error:", sys.exc_info()
	# 	exit('bye ... ')


if __name__ == "__main__":
    main()

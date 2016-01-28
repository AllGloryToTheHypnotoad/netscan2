#!/usr/bin/env python

import pcapy
import os
import sys

class CapturePackets(object):
    def __init__(self,iface='en1',filename='test.pcap',num_packets=300):
        # list all the network devices
        #print pcapy.findalldevs()

        max_bytes = 1024
        promiscuous = False
        read_timeout = 100 # in milliseconds
        pc = pcapy.open_live(iface, max_bytes, promiscuous, read_timeout)
        # pc.setfilter('tcp')
        self.dumper = pc.dump_open(filename)
        pc.loop(num_packets, self.recv_pkts) # capture packets

    # callback for received packets
    def recv_pkts(self,hdr, data):
        try:
            # print data
            self.dumper.dump(hdr, data)
        except KeyboardInterrupt:
            exit('keyboard exit')
        except:
            exit('crap ... something went wrong')
        # pc.loop(num_packets, self.recv_pkts)



def handleArgs():
	description = """
    Grabs packets from an interface and writes them to a file.

	example:

		getpackets -f filename -i iface
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('ip', help='ip address to get hostname for') # mandatory arg
	args = parser.parse_args()
	return args

def main():
	# handle inputs
	# args = handleArgs()

	# check for sudo/root privileges ??
	if os.geteuid() != 0:
		exit('You need to be root/sudo ... exiting')

	try:
		CapturePackets('en1')
	except KeyboardInterrupt:
		exit('You hit ^C, exiting ... bye')
	# except:
	# 	print "Unexpected error:", sys.exc_info()
	# 	exit('bye ... ')


if __name__ == "__main__":
    main()

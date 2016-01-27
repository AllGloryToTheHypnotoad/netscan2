#!/usr/bin/env python

import pcapy


# list all the network devices
print pcapy.findalldevs()

max_bytes = 1024
promiscuous = False
read_timeout = 100 # in milliseconds
pc = pcapy.open_live('en1', max_bytes, promiscuous, read_timeout)

pc.setfilter('tcp')
dumper = pc.dump_open('test.pcap')

# callback for received packets
def recv_pkts(hdr, data):
    try:
        print data
        dumper.dump(hdr, data)
    except KeyboardInterrupt:
        exit('keyboard exit')
    except:
        exit('crap ... something went wrong')

        packet_limit = -1 # infinite
        pc.loop(300, recv_pkts) # capture packets

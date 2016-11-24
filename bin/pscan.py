#!/usr/bin/env python

import argparse
import pprint as pp  # display info
from netscan.PassiveScan import PassiveMapper


def handleArgs():
	description = """The passive mapper primarily listens and records mDNS
	traffic.
	Example:
		pscan --file network.pcap --save network.json

	"""
	parser = argparse.ArgumentParser(description)
	args = parser.parse_args()
	return args


def main():
	# args = handleArgs()

	nmap = []
	pm = PassiveMapper()
	nmap = pm.pcap('../tests/test.pcap')
	# nmap = pm.live('en1')
	nmap = pm.filter(nmap)
	nmap = pm.combine(nmap)
	nmap = pm.combine(nmap)
	pp.pprint(nmap)

	return nmap


if __name__ == "__main__":
	main()

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
	args = handleArgs()

	map = []
	pm = PassiveMapper()
	map = pm.pcap('test.pcap')
	map = pm.filter(map)
	map = pm.combine(map)
	map = pm.combine(map)
	pp.pprint(map)

	return map


if __name__ == "__main__":
	main()

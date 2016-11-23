#!/usr/bin/env python

import sys           # get platform (linux or linux2 or darwin)
import argparse      # handle command line
# import requests      # mac api
# import json          # save data
import pprint as pp  # printing
from netscan.lib import MacLookup


def handleArgs():
	description = """Determines host vendor given the MAC address.
	example:
		getvendor 11:22:33:44:55:66 --full
		getvendor 11:22:33:44:55:66
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('mac', help='mac address of host')  # mandatory arg
	parser.add_argument('-f', '--full', help='return full json output for vendor', action='store_true', default=False)
	args = parser.parse_args()
	return args


def main():
	# handle inputs
	args = handleArgs()
	vendor = {}

	try:
		vendor = MacLookup(args.mac, args.full).vendor
		pp.pprint(vendor)
		return vendor
	except KeyboardInterrupt:
		exit('You hit ^C, exiting PassiveMapper ... bye')
	except:
		print "Unexpected error:", sys.exc_info()
		exit('bye ... ')


if __name__ == "__main__":
	main()

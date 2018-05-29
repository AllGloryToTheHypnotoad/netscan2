#!/usr/bin/env python

import sys			# get platform (linux or linux2 or darwin)
import argparse     # handle command line
# import subprocess	# use commandline
from netscan.lib import GetHostName


def handleArgs():
	description = """Find the hostname of a computer given its ip address. This
	only works on linux and OSX.

	example:

		gethostname 123.1.1.123
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('ip', help='ip address to get hostname for')  # mandatory arg
	args = parser.parse_args()
	return args


def main():
	# handle inputs
	args = handleArgs()
	hostname = 'unknown'

	# check for sudo/root privileges ??
	# if os.geteuid() != 0:
	# 	exit('You need to be root/sudo ... exiting')

	try:
		hostname = GetHostName(args.ip).name
		print hostname
		return hostname
	except KeyboardInterrupt:
		exit('You hit ^C, exiting PassiveMapper ... bye')
	except:
		print "Unexpected error:", sys.exc_info()
		exit('bye ... ')


if __name__ == "__main__":
	main()

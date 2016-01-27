#!/usr/bin/env python

import sys			# get platform (linux or linux2 or darwin)
import argparse     # handle command line
import subprocess	# use commandline

class GetHostName(object):
	def __init__(self,ip):
		"""Use the avahi (zeroconfig) tools or dig to find a host name given an
		ip address.

		in: ip
		out: string w/ host name or 'unknown' if the host name couldn't be found
		"""
		name = 'unknown'
		if sys.platform == 'linux' or sys.platform == 'linux2':
			name = self.cmdLine("avahi-resolve-address %s | awk '{print $2}'"%(ip)).rstrip().rstrip('.')
		elif sys.platform == 'darwin':
			name = self.cmdLine('dig +short -x %s -p 5353 @224.0.0.251'%ip).rstrip().rstrip('.')

		if name.find('connection timed out') >= 0: name = 'unknown'
		if name == '': name = 'unknown'

		self.name = name

	def cmdLine(self,cmd):
		return subprocess.Popen([cmd], stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]


def handleArgs():
	description = """Find the hostname of a computer given its ip address. This
	only works on linux and OSX.

	example:

		gethostname 123.1.1.123
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('ip', help='ip address to get hostname for') # mandatory arg
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
		return hostname
	except KeyboardInterrupt:
		exit('You hit ^C, exiting PassiveMapper ... bye')
	except:
		print "Unexpected error:", sys.exc_info()
		exit('bye ... ')


    if __name__ == "__main__":
    main()

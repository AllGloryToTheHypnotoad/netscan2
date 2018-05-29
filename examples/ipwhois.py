#!/usr/bin/env python

import argparse
import pprint as pp
from netscan.lib import WhoIs


def handleArgs():
	description = """Returns the record (dictionary) for an IP address
	ipwhois 184.84.180.122
		{
			u'CIDR': u'184.84.0.0/14',
			u'NetHandle': u'NET-184-84-0-0-1',
			u'NetName': u'AKAMAI',
			u'NetRange': u'184.84.0.0 - 184.87.255.255',
			u'NetType': u'Direct Allocation',
			u'Organization': u'Akamai Technologies, Inc. (AKAMAI)',
			u'OriginAS': u'',
			u'Parent': u'NET184 (NET-184-0-0-0-0)',
			u'Ref': u'http',
			u'RegDate': u'2010-03-03',
			u'Updated': u'2012-03-02'
		}
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('host', help='ip address or name')  # mandatory arg
	args = parser.parse_args()
	return args


def main():
	args = handleArgs()

	pp.pprint(WhoIs(args.host).record)


if __name__ == "__main__":
	main()

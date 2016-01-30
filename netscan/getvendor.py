#!/usr/bin/env python

import sys			# get platform (linux or linux2 or darwin)
import argparse     # handle command line
import requests		# mac api
import json         # save data

class MacLookup(object):
	def __init__(self,mac):
		self.vendor = self.get(mac)

	def get(self,mac):
		"""
		json responce from www.macvendorlookup.com:

		{u'addressL1': u'1 Infinite Loop',
		u'addressL2': u'',
		u'addressL3': u'Cupertino CA 95014',
		u'company': u'Apple',
		u'country': u'UNITED STATES',
		u'endDec': u'202412195315711',
		u'endHex': u'B817C2FFFFFF',
		u'startDec': u'202412178538496',
		u'startHex': u'B817C2000000',
		u'type': u'MA-L'}
		"""
		try:
			r = requests.get('http://www.macvendorlookup.com/api/v2/' + mac)
		except requests.exceptions.HTTPError as e:
			print "HTTPError:", e.message
			return {'company':'unknown'}

		if r.status_code == 204: # no content found, bad MAC addr
			print 'ERROR: Bad MAC addr:',mac
			return {'company':'unknown'}
		elif r.headers['content-type'] != 'application/json':
			print 'ERROR: Wrong content type:', r.headers['content-type']
			return {'company':'unknown'}
		a={}

		try:
			a['company'] = r.json()[0]['company']
			#print 'GOOD:',r.status_code,r.headers,r.ok,r.text,r.reason
		except:
			print 'ERROR:',r.status_code,r.headers,r.ok,r.text,r.reason
			a = {'company':'unknown'}

		return a

def handleArgs():
	description = """

	example:

		getvendor 11:22:33:44:55:66
	"""
	parser = argparse.ArgumentParser(description)
	parser.add_argument('mac', help='mac address of host') # mandatory arg
	args = parser.parse_args()
	return args

def main():
	# handle inputs
	args = handleArgs()
	vendor = 'unknown'

	# check for sudo/root privileges ??
	# if os.geteuid() != 0:
	# 	exit('You need to be root/sudo ... exiting')

	try:
		vendor = MacLookup(args.mac).vendor
		print vendor
		return vendor
	except KeyboardInterrupt:
		exit('You hit ^C, exiting PassiveMapper ... bye')
	except:
		print "Unexpected error:", sys.exc_info()
		exit('bye ... ')


if __name__ == "__main__":
    main()

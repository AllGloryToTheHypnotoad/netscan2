#!/usr/bin/python

from pscan import PassiveMapper
from getvendor import MacLookup
from ipwhois import WhoIs

# from nose.tools import assert_equal as eq_
# from nose.tools import assert_not_equal as neq_
# from nose.tools import assert_raises as raise_
# from nose.tools import raises

# def test_pass():
# 	"""Try to pass"""
# 	eq_(1,1)
#
# def test_fail():
# 	"""Try to fail"""
# 	eq_('bob','bob')

def test_vendor():
	ans = {u'addressL1': u'1 Infinite Loop',
	u'addressL2': u'',
	u'addressL3': u'Cupertino CA 95014',
	u'company': u'Apple',
	u'country': u'UNITED STATES',
	u'endDec': u'220083066503167',
	u'endHex': u'C82A14FFFFFF',
	u'startDec': u'220083049725952',
	u'startHex': u'C82A14000000',
	u'type': u'MA-L'}

	vendor = MacLookup('c8:2a:14:1f:18:69',True).vendor
	assert ans == vendor


def test_passive_scan():
	ans =  {'hostname': 'calculon.local',
  'ipv4': '192.168.1.8',
  'ipv6': 'fe80::ba27:ebff:fe0a:5a17',
  'mac': 'b8:27:eb:0a:5a:17',
  'tcp': [{'port': 548, 'srv': '_afpovertcp'}],
  'type': 'arp',
  'udp': []}
	map = []
	pm = PassiveMapper()
	map = pm.pcap('test.pcap')
	map = pm.filter(map)
	map = pm.combine(map)
	map = pm.combine(map)

	for host in map:
		if 'hostname' in host:
			if host['hostname'] == 'calculon.local':
				assert ans == host

def test_whois():
	ans = {u'CIDR': u'184.84.0.0/14',
	u'NetHandle': u'NET-184-84-0-0-1',
	u'NetName': u'AKAMAI',
	u'NetRange': u'184.84.0.0 - 184.87.255.255',
	u'NetType': u'Direct Allocation',
	u'Organization': u'Akamai Technologies, Inc. (AKAMAI)',
	u'OriginAS': u'',
	u'Parent': u'NET184 (NET-184-0-0-0-0)',
	u'Ref': u'http',
	u'RegDate': u'2010-03-03',
	u'Updated': u'2012-03-02'}

	who = WhoIs('184.84.180.122').record

	assert ans == who

# def test_mac():
# 	"""Test mac lookup"""
# 	ans = {'company':'unknown'}
#
# 	eq_(ans,nl.macLookup('1'))

# this doesn't work inside travis ... can't get hostname i guess???
# def test_ip():
# 	"""Test getting host ip addr, for Travis.cl this is always 127.0.0.1"""
# 	ip = nl.IP()
# # 	eq_('127.0.0.1',ip.ip)
# 	eq_(ip.ip,ip.ip,'Found: '+ip.ip)


# def main():
#
#
#
# if __name__ == "__main__":
# 	main()

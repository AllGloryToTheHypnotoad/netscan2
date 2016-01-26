#!/usr/bin/python

# import netlib as nl
# import html5

from nose.tools import assert_equal as eq_
from nose.tools import assert_not_equal as neq_
# from nose.tools import assert_raises as raise_
# from nose.tools import raises

def test_pass():
	"""Try to pass"""
	eq_(1,1)

def test_fail():
	"""Try to fail"""
	eq_('bob','bob')

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
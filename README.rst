Network Scanner
=================

.. figure:: https://imgs.xkcd.com/comics/map_of_the_internet.jpg
	:align: center


.. image:: https://travis-ci.org/walchko/netscan2.svg?branch=master
	:target: https://travis-ci.org/walchko/netscan2
.. image:: https://img.shields.io/pypi/v/netscan.svg
	:target: https://pypi.python.org/pypi/netscan/
	:alt: Latest Version
.. image:: https://img.shields.io/pypi/dm/netscan.svg
	:target: https://pypi.python.org/pypi/netscan/
	:alt: Downloads
.. image:: https://img.shields.io/pypi/l/netscan.svg
	:target: https://pypi.python.org/pypi/netscan/
	:alt: License
.. image:: https://landscape.io/github/walchko/netscan2/master/landscape.svg?style=flat
	:target: https://landscape.io/github/walchko/netscan2/master
	:alt: Code Health

Simple python script which uses pcap, arp-scan, and `avahi <http://www.avahi.org>`__ to:

1. Find hosts that are on the LAN passively
2. Uses an arp-ping to actively identify hosts
3. Scan each host to determine open ports and services
4. Store record of hosts in JSON file, html webpage, or prints to screen

**Note:** Since IP addresses change, the hosts are finger printed via their MAC address.

Alternatives
--------------

`Fing <http://www.overlooksoft.com/fing>`__ is a great and fast network scanner, I have
their app on my iPad. However, the ``fing`` commandline tool for
RPi I have noticed errors in the MAC address and therefor don't trust it for this
application.

Install
--------

Pre-requisites::

	brew install pcap arp-scan

or

::

	sudo apt-get install libpcap-dev arp-scan

Download and unzip, then from inside the package::

	python setup.py install

If you are working on it::

	pip install -e .

Run
------------

To run::

	netscan
	ascan
	pscan
	gethostname
	getvendor
	ipwhois


License
----------

**The MIT License (MIT)**

Copyright (c) 2015 Kevin J. Walchko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

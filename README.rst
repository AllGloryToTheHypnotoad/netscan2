Network Scanner
=================

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
    
Simple python script which uses pcap, arp-scan, and `avahi <http://www.avahi.org>`__ to:

1. Find hosts that are on the LAN passively
2. Uses an arp-ping to actively identify hosts
3. Scan each host to determine open ports and services
4. Store record of hosts in JSON file, html webpage, or prints to screen

**Note:** Since IP addresses change, the hosts are finger printed via their MAC address. 

**Note:** On linux it uses avahi to get hostnames, but doesn't work on OSX

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

	sudo python setup.py install

If you are working on it::

	sudo python setup.py develop

Run Active
------------

To see all run time options::

	netscan --help

Basic, to search for addresses on your network, use::

	sudo netscan -a -r 5000 -i en1


-i, --interface   interface to listen to, ex. en0, en1
-r, --range       what ports to scan (1 ... n), where n in this case is 5000 (upper limit)

The default is to display results to the screen.

**Note:** This has to be run as root


Run Passive
-------------

::

	sudo netscan -p 1000 -j network.json -i en1

-p, --passive  conduct passive mode, scan 1000 packets and output results
-j, --json     output results to a json file

Run Active/Passive
--------------------

::

	sudo netscan -a -p 1000 -w network.html -i en1

-w, --webpage  output to webpage name network.html


Make HTML from a JSON file
-----------------------------

::

	html5 network.json

JSON files can be hard to read (one long string), this puts it into an easier form to 
digest.

To Do
------

- remove ``arp-scan`` and code directly in python
- add ability to feed a earlier json scan into program and wol to bring up sleeping hosts
- better documentation
- add a verbose argument, sometimes it seems like nothing is happening
- currently not using awake, netaddr, or commands ... need to fix 


Web Server
-----------

This is designed to work with Node.js `netscan <http://github.com/walchko/node-netscan>`__ but that is still work in progress.


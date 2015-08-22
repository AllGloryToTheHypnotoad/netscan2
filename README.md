# Network Scanner

[![Build Status](https://travis-ci.org/walchko/netscan2.svg?branch=master)](https://travis-ci.org/walchko/netscan2)

Simple python script which uses pcap and [avahi](http://www.avahi.org) to:

1. Find hosts that are on the LAN passively
2. Uses an arp-ping to actively identify hosts
3. Scan each host to determine open ports and services
4. Store record of hosts in YAML file
5. Creates a webpage for the server to display

**Note:** Since IP addresses change, the hosts are finger printed via their MAC address. 

## Alternatives

* [Fing](http://www.overlooksoft.com/fing) is a great and fast network scanner, I have 
their app on my iPad. However, the `fing` commandline tool for 
RPi I have noticed errors in the MAC address and therefor don't trust it for this 
application.

## Install and Usage

Pre-requisites:

	brew install pcap arp-scan

Download and unzip, then from inside the package:

	sudo python setup.py install

If you are working on it:

	sudo python setup.py develop

### Run Active

To see all run time options:

	netscan --help

Basic, to search for addresses on your network, use:

	sudo netscan -a -r 5000 -i en1

- i  interface to listen to, ex. en0, en1
- r  what ports to scan (1 ... n), where n in this case is 5000 (upper limit)

The default is to display results to the screen.

**Note:** This has to be run as root


### Run Passive

	sudo netscan -p 1000 -j network.json -i en1

- p  conduct passive mode, scan 1000 packets and output results
- j  output results to a json file

### Run Active/Passive

	sudo netscan -a -p 1000 -w network.html -i en1

- w  output to webpage name network.html


### Make HTML from a JSON file

	html5 network.json

JSON files can be hard to read (one long string), this puts it into an easier form to 
digest.

## To Do

[ ] remove `arp-scan` and code directly in python
[ ] add ability to feed a earlier json scan into program and wol to bring up sleeping hosts






-----


# Old -- ignore all below, need to fix!

### Init.d

Here is the script I put in `/etc/init.d/netscan` to have it run as `root` automatically.
Modify to fit your application.

	# /etc/init.d/netscan
	#

	# Some things that run always
	DAEMON_USER=root
	DIR=/home/pi/github/netscan
	DAEMON_NAME=netscan
	DAEMON=$DAEMON_NAME
	DAEMON_full="netscan -- -y /mnt/usbdrive/network.yaml  -p /mnt/usbdrive/network.html "
	PIDFILE=/var/run/$DAEMON_NAME.pid

	. /lib/lsb/init-functions

	# Carry out specific functions when asked to by the system
	case "$1" in
	  start)
		echo "Starting netscan"
		log_daemon_msg "Starting system $DAEMON_NAME daemon"
		start-stop-daemon --start --background --pidfile $PIDFILE --make-pidfile --user $DAEMON_USER --chuid $DAEMON
	_USER --startas $DAEMON_full 
		log_end_msg $?
		;;
	  stop)
		log_daemon_msg "Stopping system $DAEMON_NAME daemon"
		start-stop-daemon --stop --pidfile $PIDFILE --retry 10
		log_end_msg $?
		;;
	  status)
		status_of_proc $SERVER_NAME $SERVER && status_of_proc $DAEMON_NAME $DAEMON && exit 0 || exit $?
		#status_of_proc $SERVER_NAME $SERVER && exit 0 || exit $?    
		;;
	  *)
		echo "Usage: /etc/init.d/netscan {start|status|stop}"
		exit 1
		;;
	esac

	exit 0

Now a quick `sudo /etc/init.d/netscan start` or `sudo /etc/init.d/netscan stop` can get things going or end them easily.

A full listing of known ports are available on [wikipedia](http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

## Data Base

Currently this is just a simple python dictionary which gets stored on the hard drive as a YAML file.

	{'xx:xx:xx:xx:xx:xx': {'hostname': 'unknown',
						   'ipv4': '192.168.12.55',
						   'lastseen': '20150208-21:06',
						   'ports': {53: '[tcp]domain',
									 137: '[udp]netbios-ns',
									 139: '[tcp]netbios-ssn',
									 445: '[tcp]microsoft-ds',
									 548: '[tcp]afp',
									 5009: '[tcp]airport-admin',
									 5353: '[udp]zeroconf',
									 10000: '[tcp]snet-sensor-mgmt'},
						   'status': 'up',
						   'type': 'Apple'},
	 'xx:xx:xx:xx:xx:xx': {'hostname': 'unknown',
						   'ipv4': '192.168.12.56',
						   'lastseen': '20150208-21:06',
						   'ports': {5000: '[tcp]upnp', 5353: '[udp]zeroconf'},
						   'status': 'up',
						   'type': 'Apple'},
	 'xx:xx:xx:xx:xx:xx': {'hostname': 'unknown',
						   'ipv4': '192.168.12.57',
						   'lastseen': '20150208-21:06',
						   'ports': {5000: '[tcp]upnp', 5353: '[udp]zeroconf'},
						   'status': 'up',
						   'type': 'Apple'}}


# Node.js server

I am still working on this and will probably make changes. There are several things I 
have served up by node.js. Here is my `/etc/init.d/nodejs` script:

	# /etc/init.d/nodesjs
	#

	# Some things that run always
	DAEMON_USER=root
	DIR=/usr/local/bin
	DAEMON_NAME=http-server
	DAEMON=$DIR/$DAEMON_NAME
	PIDFILE=/var/run/$DAEMON_NAME.pid
	DAEMON_full="$DAEMON -- /mnt/usbdrive -p 9000 -s"

	. /lib/lsb/init-functions

	# Carry out specific functions when asked to by the system
	case "$1" in
	  start)
		echo "Starting Nodejs HTTP Server"
			echo $DAEMON_full
		log_daemon_msg "Starting system $DAEMON_NAME daemon"
		start-stop-daemon --start --background --pidfile $PIDFILE --make-pidfile --user $DAEMON_USER --chuid $DA
	EMON_USER --startas $DAEMON_full
			log_end_msg $?
		;;
	  stop)
		log_daemon_msg "Stopping system $DAEMON_NAME daemon"
		start-stop-daemon --stop --pidfile $PIDFILE --retry 10
		log_end_msg $?
		;;
	  status)
		status_of_proc status_of_proc $DAEMON_NAME $DAEMON && exit 0 || exit $?
		;;
	  *)
		echo "Usage: /etc/init.d/nodejs-movies {start|status|stop}"
		exit 1
		;;
	esac

	exit 0

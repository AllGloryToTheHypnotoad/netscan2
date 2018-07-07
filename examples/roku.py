#!/usr/bin/env python2

from __future__ import print_function, division
import socket

from io import BytesIO  # in memory binary strings
from collections import namedtuple
try:
    # Py 2.7
    import httplib
except ImportError:
    # Py 3
    import http.client as httplib

# fix path for now
import sys
sys.path.append("../")
from netscan.lib import GetHostName, MacLookup


import sys
import subprocess  # use commandline
import requests    # whois
import re
from netaddr import valid_ipv4, valid_mac
import os
# import platform  # socket alternative to get hostname
import socket


def command(cmd):
    return subprocess.Popen(
        [cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True).communicate()[0]


HostInfo = namedtuple("HostInfo", "cidr netname netrange org updated")


def whois(ip):
    """
    Given a valid ipv4 address, it returns the whois info as a namedtuple:

    whois('172.217.12.4')
    HostInfo(cidr=u'172.217.0.0/16', netname=u'GOOGLE', netrange=u'172.217.0.0 - 172.217.255.255', org=u'Google LLC (GOGL)', updated=u'2012-04-16')
    """
    if not valid_ipv4(ip):
        print('Error: the IPv4 address {} is invalid'.format(ip))
        return
    rec = requests.get('http://whois.arin.net/rest/ip/{}.txt'.format(ip))
    if rec.status_code != 200:
        print('Error')
        return
    ans = {}
    r = re.compile(r"\s\s+")
    b = rec.text.split('\n')
    for i, s in enumerate(b):
        if len(s) == 0:
            b.pop(i)
        elif s[0] == u'#':
            b.pop(i)
    print('---------')
    print(b)
    for l in b:
        if l and l[0] != '#':
            l = r.sub('', l)
            a = l.split(':')
            ans[a[0]] = a[1]

    return HostInfo(
        ans['CIDR'],
        ans['NetName'],
        ans['NetRange'],
        ans['Organization'],
        ans['Updated'])


def get_host_name(ip):
    """
    Use the avahi (zeroconfig) tools or dig to find a host name given an
    ip address.

    in: ip
    out: string w/ host name or 'unknown' if the host name couldn't be found
    """
    # ret = None
    # handle invalid ip address
    if not valid_ipv4(ip):
        print('Error: the IPv4 address {} is invalid'.format(ip))
        return 'unknown'

    # handle a localhost ip address
    if ip == '127.0.0.1' or ip == 'localhost':
        return socket.gethostname()

    # ok, now do more complex stuff
    if sys.platform == 'linux' or sys.platform == 'linux2':
        name = command("avahi-resolve-address {} | awk '{print $2}'".format(ip)).rstrip().rstrip('.')
    elif sys.platform == 'darwin':
        name = command('dig +short -x {} -p 5353 @224.0.0.251'.format(ip)).rstrip().rstrip('.')
    else:
        raise Exception("get_host_name is unsupported on your OS, get a better one :)")

    # detect any remaining errors
    if name.find('connection timed out') >= 0 or len(name) == 0:
        name = 'unknown'

    return name


class SSDPResponse(object):
    """
    Simple class to find Roku's on your network. I don't remember where I found
    it online, but I made it Python 2/3 compatable and changed some stuff.
    """
    class _FakeSocket(BytesIO):
        def makefile(self, *args, **kw):
            return self

    def __init__(self, response):
        s = self._FakeSocket(response)
        r = httplib.HTTPResponse(s)
        r.begin()
        self.location, self.port = r.getheader("location").replace('http://','').replace('/','').split(':')
        self.usn = r.getheader("usn")
        self.st = r.getheader("st")
        self.cache = r.getheader("cache-control").split("=")[1]
        self.mac = r.getheader("WAKEUP").split(";")[0].split("=")[1].upper()
        self.server = r.getheader("server")
        self.hostname = "Roku-" + self.usn.split(":")[3]
        self.msg = r.msg

    def __repr__(self):
        return "SSDPResponse ------------\n  {hostname}\n  {location}:{port}\n  {mac}\n  {usn}\n  {server}\n".format(**self.__dict__)


def discover(service, timeout=5, retries=1, mx=3):
    group = (b"239.255.255.250", 1900)
    message = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {0}:{1}',
        'MAN: "ssdp:discover"',
        'ST: {st}',
        'MX: {mx}',
        '',
        ''])
    socket.setdefaulttimeout(timeout)
    responses = []
    for _ in range(retries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(message.format(*group, st=service, mx=mx).encode('utf-8'), group)
        while True:
            try:
                resp = SSDPResponse(sock.recv(1024))
                # responses[resp.location] = resp
                responses.append(resp)
            except socket.timeout:
                break
    return responses


if __name__ == "__main__":
    # print("hostname:", get_host_name("192.168.86.213"))
    print(whois('172.217.12.4'))
    exit(0)
    # start scan
    print('** scan **')
    ans = discover("roku:ecp")
    for roku in ans:
        print(roku)

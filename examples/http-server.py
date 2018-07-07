#!/usr/bin/env python

# put into netscan2

from __future__ import division, print_function
import multiprocessing as mp
import time
import bjoern
from jinja2 import Environment
import os

from roku import discover

# try to grab simplejson, if not fall back to the built in json
try:
    import simplejson as json
except ImportError:
    import json
# loader = jinja2.FileSystemLoader('./index.html')
# env = jinja2.Environment(loader=loader)
# template = env.get_template('')

# fix path for now
# import sys
# sys.path.append("../")

class Watcher(object):
    """
    A simple class to watch if a file has changed.

    https://stackoverflow.com/questions/182197/how-do-i-watch-a-file-for-changes/49007649#49007649
    """

    def __init__(self, watch_file):
        """
        watch_file - what file to watch
        """
        self._cached_stamp = 0
        self.filename = watch_file

    def change(self):
        """
        Has the file changed?
        return True - file has changed
               False - the file is still the same
        """
        ret = False
        stamp = os.stat(self.filename).st_mtime
        if stamp != self._cached_stamp:
            self._cached_stamp = stamp
            ret = True
        return ret


# get network data and watch for update
filename = 'network.json'
watcher = Watcher(filename)
data = {}

page = """
<!DOCTYPE html>
<html>
<header>
<link href="/assets/techno-font.css" rel="stylesheet">
<!--
<link rel="stylesheet" href="https://unpkg.com/purecss@1.0.0/build/pure-min.css">
<meta name="viewport" content="width=device-width, initial-scale=1">
-->
<style>
h1 {
    text-align: center;
}
table.center {
    margin-left:auto;
    margin-right:auto;
}
table {
    width: 75%;
    border-collapse: collapse;
   border: 2px solid gray;
}
th, td {
   border: 1px solid black;
}
td, th {
    border: 1px solid #ddd;
    padding: 8px;
}
tr:nth-child(even){
    background-color: #f2f2f2;
}
tr:hover {
    background-color: #ddd;
}
th {
    padding-top: 12px;
    padding-bottom: 12px;
    text-align: left;
    background-color: DodgerBlue;
    color: white;
}
</style>
</header>
<body>

<i class="tf-archlinux tf-128" style="color:dodgerblue;"></i>

<h1>{{ title }}</h1>

<!-- <table class="pure-table pure-table-striped"> -->
<table class="center">
<tr>
    <th> Hostname </th>
    <th> Status </th>
    <th> IPv4 </th>
    <th> MAC </th>
    <th> Manufactorer </th>
    <th> Open Ports </th>
</tr>

<tbody>
{% for item in items %}
<tr>
    <td>{{item.hostname}}</td>
    <td>{{item.status}}</td>
    <td>{{item.ip}}</td>
    <td>{{item.mac}}</td>
    <td>{{item.company}}</td>
    <td>{{item.openports}}</td>
</tr>
{% endfor %}
</tbody>
</table>

</body>
</html>
"""
template = Environment().from_string(page)


def readAsset(file_path, kind):
    if kind == 'woff':
        mime = 'application/font-woff'
    elif kind == 'tff':
        mime = 'application/font-tff'
    elif kind == 'css':
        mime = 'text/css'

    # get the absolute path to this directory
    path = os.path.abspath(os.path.dirname(__file__))
    file_path = path + file_path

    print(">> reading file: {}".format(file_path))

    with open(file_path) as fd:
        font = fd.read()
    response_body = font
    response_headers = [
        ('Content-Type', mime)
    ]
    return (response_headers, response_body)


def app(environ, start_response):
    # I don't like globals
    global watcher
    global filename
    global data

    try:
        # why?
        # just run this through shared memory
        #
        # old network scanner had: hostname, ipv4, mac, company name
        # new: hostname, up/down, ipv4, mac, company, ports
        if watcher.change():
            print(">> updating data from {}".format(filename))
            with open(filename) as fd:
                data = json.load(fd)
            print(data)
        else:
            print('>> no data change')
    except Exception as e:
        data = {}
        print(e)
        print(">> Error loading file: {}".format(filename))

    # response_body = urls[environ['PATH_INFO']]
    if environ['PATH_INFO'] == '/':
        global template
        # render html body as a binary string(utf-8)
        response_body = template.render(
            title="Network {}".format("1.2.3.x"),
            items=data).encode('utf-8')
        status = b'200 OK'
        response_headers = [
            (b'Content-Type', b'text/html'),
            (b'Content-Length', str(len(response_body)).encode('utf-8'))
        ]
        start_response(status, response_headers)
        return [response_body.encode('utf-8')]

    elif environ['PATH_INFO'].find('.css') > 0:
        response_headers, response_body = readAsset(environ['PATH_INFO'], 'css')
        start_response('200 OK', response_headers)
        return [response_body.encode('utf-8')]

    elif environ['PATH_INFO'].find('.woff') > 0:
        response_headers, response_body = readAsset(environ['PATH_INFO'], 'woff')
        start_response('200 OK', response_headers)
        return [response_body]

    elif environ['PATH_INFO'].find('.tff') > 0:
        response_headers, response_body = readAsset(environ['PATH_INFO'], 'tff')
        start_response('200 OK', response_headers)
        return [response_body]

    else:
        # raise Exception(">> Invalid path: {}".format(environ['PATH_INFO']))
        print(">> Invalid path: {}".format(environ['PATH_INFO']))
        status = '404 OK'
        response_body = 'Path not valid: {}'.format(environ['PATH_INFO'])
        response_headers = [
            ('Content-Type', 'text/plain'),
            ('Content-Length', str(len(response_body)))
        ]
        start_response(status, response_headers)
        return [response_body.encode('utf-8')]


def scanner(e):
    # this searches for computers on the network
    while e.is_set:
        print('** scan **')
        ans = discover("roku:ecp")
        for roku in ans:
            print(roku)
        time.sleep(5)
    print("** scanner shutting down now **")


if __name__ == "__main__":
    # start recon thread
    e = mp.Event()
    e.set()
    p = mp.Process(target=scanner, args=(e,), name='scanner')
    p.start()

    host = "0.0.0.0"
    port = 8000
    print("Starting on: {}:{}".format(host, port))
    bjoern.listen(app, host, port, reuse_port=True)

    try:
        bjoern.run()
    except KeyboardInterrupt:
        # i don't think this is working
        e.clear()
        p.join(1)

# class Analyzer(object):
#
#     def getHostName(self,ip):
#         """Use the avahi (zeroconfig) tools to find a host name ... this only works
#         on Linux using the avahi tools.
#
#         in: ip
#         out: string w/ host name
#         """
#         name = 'unknown'
#         if sys.platform == 'linux' or sys.platform == 'linux2':
#             cmd = ["avahi-resolve-address %s | awk '{print $2}'"%(ip)]
#             #name  = self.runProcess(cmd)
#             name = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]
#             name = name.rstrip()
#             if name == '': name = 'unknown'
#         return name
#
#     def find(self,net,ip):
#         """
#         finds a recored in a list
#         """
#         return next(x for x in net if x['ipv4'] == ip)
# #
# #        print 'find:',ip
# #        for r in net:
# #            print r['ipv4']
# #            if r['ipv4'] == ip: return r
#
#     def check(self,net,rec):
#         """
#         check if an ipv4 host record already exists
#         """
#         for r in net:
#             if r['ipv4'] == rec['ipv4']: return True
#         return False
#
# #    def checkSrv(self,ar,svc):
# #        """
# #        check if a service record already exists
# #        """
# #        for s in ar:
# #            if s == svc: return True
# #        return False
#
#     def merge(self,nmap,active):
#         """
#         Merges the active and passive scans
#
#         map - records found during passive mapping
#         active - active scan results
#
#         *---
#           AAAA: fe80::ca2a:14ff:fe1f:1869 is Dalek.local
#         *---
#           A: 192.168.1.13 is Dalek.local
#         *---
#           ARP: 192.168.1.13 is c8:2a:14:1f:18:69
#         *---
#           TXT: 192.168.1.19 _device-info[_tcp] type: 16
#         *---
#         """
#
#         for i in active:
#             nmap.append(i)
#
#         net = []
#
#         # go thru everything passively collected and build a network map
#         for i in nmap:
#             # mdns are the primary good ones
#             if i['type'] == 'mdns':
#                 rec={'tcp':[],'udp':[]}
#                 ar = i['rr']
#
#                 # for each mdns record type: a, aaaa, srv, ...
#                 for rr in ar:
#                     if rr['type'] == 'a':
#                         rec['ipv4'] = rr['ipv4']
#                         rec['hostname'] = rr['hostname']
#                     elif rr['type'] == 'aaaa': rec['ipv6'] = rr['ipv6']
#                     elif rr['type'] == 'srv':
#                         srv = ( rr['port'], rr['srv'][1:] )
#                         if rr['proto'] == '_tcp':
#                             rec['tcp'].append(srv)
#                         elif rr['proto'] == '_udp':
#                             rec['udp'].append(srv)
#
#                 # see if mdns has already been found
#                 if 'ipv4' in rec:
#                     if not self.check(net,rec): net.append(rec)
#
#         # arp is the other most useful passively collected, go through and find hosts
#         # not found in the passive mapping or update hosts with other info (mac, ports, etc)
#
#         # start with arp to get all hosts found
#         for i in nmap:
#             if i['type'] == 'arp':
#                 found = False
#                 # see if the ip has been found, if so, add the mac addr
#                 for host in net:
#                     if i['ipv4'] == host['ipv4']:
#                         host['mac'] = i['mac']
#                         host['os'] = macLookup(i['mac'])['company']
#                         found = True
#                 # if not found, then add a new host record
#                 if not found:
#                     net.append({'ipv4': i['ipv4'], 'mac': i['mac'], 'os': macLookup(i['mac'])['company']})
#
#         # now do ports after all hosts found
#         for i in nmap:
#             if i['type'] == 'portscan':
# #                print 'portscan',i['ipv4'],i['ports']
#                 host = self.find(net,i['ipv4'])
#                 if 'tcp' not in host:
#                     host['tcp'] = i['ports']
#                 else:
#                     host['tcp'] = list(set( i['ports'] + host['tcp'] )) # combine port arrays
#
#                 if 'udp' not in host:
#                     host['udp'] = []
#
#
#
#         # go through everything and add some other info
#         for i in net:
#             if 'hostname' not in i: i['hostname'] = self.getHostName( i['ipv4'] )
#             if 'mac' in i and 'os' not in i: i['os'] = macLookup(i['mac'])['company']
#
#             i['lastseen'] = str(datetime.datetime.now().strftime('%H:%M %a %d %b %Y'))
#             i['status'] = 'up'
#
#             if 'tcp' in i and i['tcp']: i['tcp'] = list(set( i['tcp'] ))
#             if 'udp' in i and i['udp']: i['udp'] = list(set( i['udp'] ))
#
#         return net

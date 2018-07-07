#!/usr/bin/env python3

from zeroconf import ServiceBrowser, Zeroconf


class MyListener:

    def remove_service(self, zeroconf, type, name):
        print("\nService %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("\nService %s added\nservice info: %s" % (name, info))


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_ipp._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.close()

# #!/usr/bin/env python
#
# from pscan import PassiveMapper
# from getvendor import MacLookup
# from ipwhois import WhoIs
# from gethostname import GetHostName
# import argparse
#
#
# def handleArgs():
# 	description = """This is the main network scanner and can optionally use
#     both passive and/or active methods to determine the hosts that are
#     operating on your network and ports are open. All data is saved or transmitted
#     in json format. The results can be saved locally, printed to screen, or
#     forwarded to another host.
#     Examples:
#         netscan --passive --save network.json
#         netscan --active --save network.json
#         netscan --active --passive --post http://othercomputer.com
#         netscan --passive --forever
# 	"""
# 	parser = argparse.ArgumentParser(description)
# 	args = parser.parse_args()
# 	return args
#
#
# def main():
# 	args = handleArgs()
#
#
#
# if __name__ == "__main__":
# 	main()

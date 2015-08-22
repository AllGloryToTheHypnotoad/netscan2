#!/usr/bin/python
#

import yaml

class YamlDoc:	
	"""
	Simple class to read/write yaml docs to dict's
	"""
	def read(self,filename):
		"""Reads a Yaml file"""
		# need better testing, breaks if file missing
		try:
			f = open(filename,'r')
			file = yaml.safe_load(f)
			f.close()
			return file
		except IOError:
			file = dict()
			print '[-] YamlDoc: IOError'
		
	def write(self,filename,data):
		"""Writes a Yaml file"""
		f = open(filename,'w')
		yaml.safe_dump(data,f)
		f.close()
		

if __name__ == '__main__':
    print 'nothing to do here ... move along, move along :)'
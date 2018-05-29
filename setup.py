from setuptools import setup
import os
from netscan import __version__ as VERSION
from build_utils import BuildCommand
from build_utils import PublishCommand
from build_utils import BinaryDistribution


PACKAGE_NAME = 'netscan'
BuildCommand.pkg = PACKAGE_NAME
PublishCommand.pkg = PACKAGE_NAME
PublishCommand.version = VERSION


setup(
	name='netscan',
	version=VERSION,
	description='A simple Python active and passive network scanner for linux and OSX',
	long_description=open('README.rst').read(),
	keywords='network scanner active passive dpkt html',
	url='https://github.com/walchko/netscan2',
	author='Kevin Walchko',
	author_email='walchko@users.noreply.github.com',
	license='MIT',
	classifiers=[
		'Development Status :: 4 - Beta',
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python :: 2.7',
		'Operating System :: Unix',
		'Operating System :: MacOS :: MacOS X',
		'Operating System :: POSIX',
		'Topic :: Utilities',
		'Topic :: System :: Shells',
		'Environment :: Console'
	],
	cmdclass={
		'publish': PublishCommand,
		'make': BuildCommand
	},
	packages=['netscan'],
	install_requires=['requests', 'pcapy', 'dpkt', 'netaddr'],
	# scripts=[
	# 	'bin/ascan.py',
	# 	'bin/pscan.py',
	# 	'bin/gethostname.py',
	# 	'bin/getvendor.py',
	# 	'bin/ipwhois.py'
	# ]
	# entry_points={
	# 	'console_scripts': [
	# 		'netscan=netscan.netscan:main',
	# 		'capture=netscan.capture:main',
	# 		'pscan=netscan.pscan:main',
	# 		'ascan=netscan.ascan:main',
	# 		'getvendor=netsan.getvendor:main',
	# 		'gethostname=netscan.gethostname:main',
	# 		'ipwhois=netscan.ipwhois:main'
	# 	],
	# },
)

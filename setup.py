from setuptools import setup
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='netscan',
    version='2.1.2',

    description='A simple Python active and passive network scanner for linux and OSX',
    long_description=read("README.rst"),
    keywords='network scanner active passive dpkt html',

    # The project's main homepage.
    url='https://github.com/walchko/netscan2',

    # Author details
    author='Kevin Walchko',
    author_email='kevin.walchko@outlook.com',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        #'Intended Audience :: Developers',
        #'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2.7',
        #'Programming Language :: Python :: 3',
        #'Programming Language :: Python :: 3.2',
        #'Programming Language :: Python :: 3.3',
        #'Programming Language :: Python :: 3.4',
        
        # Operating systems this runs on
        'Operating System :: Unix',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        
        # what does this do?
        'Topic :: Utilities',
        'Topic :: System :: Shells',
        'Environment :: Console'
    ],
	
    packages=['netscan'],
    install_requires=['awake','requests','pcapy','dpkt','netaddr'],
    entry_points={
        'console_scripts': [
            'netscan=netscan.netscan:main',
            'html5=netscan.html5:main',
        ],
    },
)

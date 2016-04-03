#! /usr/bin/python

"""
This script installs PA_Capturer.

PA_Capturer is a wrapper to tshark that create a sqlite file from captured packet.
"""

__author__ = 'Mohammad Fatemipour'
__email__ = 'm.fatemipour@gmail.com'
__date__ = '2016-Apr-2'
__version__ = '1.0.0'

from distutils.core import setup


setup(name='sshark',
	packages = ['sshark'],
      author=__author__,
      author_email=__email__,
      version=__version__,
	description='sshark is a wrapper to tshark that create a sqlite file from captured packet.',
	download_url = 'https://github.com/mfs-git/sshark/1.0.0',
	keywords = ['tshark', 'sqlite', 'capture', 'sshark'],
      scripts=['src/sshark.py'],
      data_files=[('config', ['src/sshark_config.xml'])])

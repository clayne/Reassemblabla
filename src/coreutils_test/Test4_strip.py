#!/usr/bin/python
#-*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import sys
import os
import subprocess
import re
from optparse import OptionParser
import binascii 
from global_variables import *

def get_binary_file(mypath):
	filelist = []
	for filename in os.listdir(mypath):
		filename = mypath + '/' + filename

		if os.path.isfile(filename):
			if os.access(filename, os.X_OK):
				filelist.append(filename)
	return filelist
	
if len(sys.argv) != 2:
	print "[*] Usage : Test4_strip.py [PATH of binary]"
	sys.exit(1)
mypath = sys.argv[1]

filelist = get_binary_file(mypath)
i = 0
for filename in filelist:
	i += 1
	cmd = ""
	cmd += "strip "
	cmd += filename
	try:
		print cmd
		subprocess.check_output(cmd, shell=True)
	except:
		print "  error"

print ""
print ""
print "[*] strip completed!" 

raw_input()
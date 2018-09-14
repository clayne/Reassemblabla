#!/usr/bin/python
#-*- coding: utf-8 -*-
#from __future__ import print_function
from os import listdir
from os.path import isfile, join
import os
import subprocess
import sys 
import os
import binascii
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools import *
from keystone import *
import pwn
from binary2dic import *
from etc import *
from symbolize import *
from global_variables import *
import stat

# 설명 : 모든 [PATH] 의 실행바이너리들에 대해서 리어셈블라블라를 돌리고, 그 결과를 ./folder 에 저장합니다. 
# Usage : python Test1.py ~/coreutils/src/

def get_binary_file(mypath):
	filelist = []
	for filename in os.listdir(mypath):
		filename = mypath + filename
		if os.path.isfile(filename) and os.access(filename, os.X_OK):
			filelist.append(filename)
	return filelist
	

# main
if len(sys.argv) != 2:
	print "[*] Usage : Test1.py [PATH of coreutils binary]"
	sys.exit(1)
mypath = sys.argv[1]

filelist = get_binary_file(mypath)

i = 0
for filename in filelist:
	i += 1
	cmd = ""
	cmd += "python Reassemblablabla_x86.py -f "
	cmd += filename
	cmd += " -l folder --align --comment"
	print " [{}] {}".format(str(i), filename)
	try:
		subprocess.check_output(cmd, shell=True)
	except:
		print "  error"

print ""
print ""
print "[*] Disassemble finished!" 
print "    press [ENTER] key to move disassembled files to coreutils/src directory..."

raw_input()











	 
	


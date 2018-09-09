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

# python tmp_assemble_coreutils_and_moveit_to_coreutils_src.py ~/coreutils/src/ /home/osboxes/coreutils/src

def get_binary_file(mypath):
	filelist = []
	for filename in os.listdir(mypath):
		filename_only = filename
		filename = mypath + filename
		if os.path.isfile(filename) and os.access(filename, os.X_OK):
			filelist.append(filename_only)
	return filelist


# main
if len(sys.argv) != 3:
	print "[*] Usage : tmp.py [PATH of reassembly files] [absolute PATH of coreutils/src]"
	sys.exit(1)
frompath = sys.argv[1]
destpath = sys.argv[2]

filelist = get_binary_file(destpath) # destpath 에 있는 바이너리의 이름을 구해온다. 
print filelist
print ""
print ""


# cd frompath
cmd  = ''
cmd += 'cd '
cmd += frompath
subprocess.check_output(cmd, shell=True)

i = 0
for filename in filelist:
	i += 1
	cmd =  ""
	cmd += 'cd '
	cmd += frompath
	cmd += " && ./"
	cmd += filename
	cmd += "_assemble.sh"
	print " [{}] {}".format(str(i), filename)
	try:
		subprocess.check_output(cmd, shell=True)
		cmd2  = ""
		cmd2 += "cd "
		cmd2 += frompath
		cmd2 += " && "
		cmd2 += "cp "
		cmd2 += filename
		cmd2 += "_reassemblable "
		cmd2 += destpath
		cmd2 += "/"
		cmd2 += filename # filename 으로 복사 
		try:
			subprocess.check_output(cmd2, shell=True)
		except:
			print "\n  ...error on moving..\n"
	except:
		print "\n  ...error on assemble\n"
	
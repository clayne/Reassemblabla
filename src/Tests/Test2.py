#!/usr/bin/python
#-*- coding: utf-8 -*-
#from __future__ import print_function
from os import listdir
from os.path import isfile, join
import subprocess
import sys 
import os
import binascii
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools import *
from keystone import *
import pwn
import stat

# python Test2.py ~/coreutils/src/ /home/osboxes/coreutils/src
# 설명 : [PATH1]에 위치한 리어셈블리 파일을 어셈블합니다.
#        그리고나서 [PATH2] 에다가 cp 해둡니다. 
# 이 스크립트를 마치고 나서는 그 폴더로 가서 make check 해주면 됩니다. 

def get_binary_file(mypath):
	filelist = []
	for filename in os.listdir(mypath):
		filename_only = filename
		filename = mypath + '/' + filename
		if os.path.isfile(filename) and os.access(filename, os.X_OK):
			filelist.append(filename_only)
	return filelist


# main
if len(sys.argv) != 3:
	print "[*] Usage : Test2.py [PATH of reassembly files] [absolute PATH of coreutils/src]"
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
	#cmd += "_assemble.sh"
	cmd += "_compile.sh"
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
	

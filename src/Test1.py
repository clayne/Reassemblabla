#!/usr/bin/python
#-*- coding: utf-8 -*-
#from __future__ import print_function
import os
import subprocess
import sys 
import binascii
from elftools import *
from keystone import *
import pwn
import stat
from multiprocessing import Process
from multiprocessing import Pool

# 설명 : 모든 [PATH] 의 실행바이너리들에 대해서 리어셈블라블라를 돌리고, 그 결과를 ./folder 에 저장합니다. 
# Usage : python Test1.py ~/coreutils/src/


idx = [0]

def get_binary_file(mypath):
	filelist = []
	for filename in os.listdir(mypath):
		filename = mypath + '/' + filename

		if os.path.isfile(filename):
			if os.access(filename, os.X_OK):
				filelist.append(filename)
	return filelist


def run(filename):
	cmd = ""
	cmd += "python Reassemblablabla_x86.py -f "
	cmd += filename
	# cmd += " -l folder --align --comment --shrinksize" # shrink the size by thinning local symbols.
	cmd += " -l folder --align --comment >  z" # shrink the size by thinning local symbols.
	
	
	try:
		os.system(cmd)
		idx[0] += 1                          
		print "[{}]. {}".format(idx[0], filename)
	except:
		print "  error"



if __name__=='__main__':

	if len(sys.argv) != 2:
		print "[*] Usage : Test1.py [PATH of coreutils binary]"
		sys.exit(1)
	mypath = sys.argv[1]
	
	filelist = get_binary_file(mypath)
	index = 0
	
	
	
	pool = Pool(processes=8)
	pool.map(run, filelist)
	
	
	print ""
	print ""
	print "[*] Disassemble finished!" 
	print "    press [ENTER] key to move disassembled files to coreutils/src directory..."
	
	raw_input()










	 
	


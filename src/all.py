#!/usr/bin/python
#-*- coding: utf-8 -*-
from os import listdir
from os.path import isfile, join
import os
import subprocess
# 현재디렉터리 대상으로 해서 모두 스크립트돌려보기
# 우선은 ELF 32-bit LSB shared object 대상으로만... (PIE는 노노)

cmd = "echo ----------------- >> logs"
mypath = "/bin/"
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
for i in xrange(len(onlyfiles)):
	onlyfiles[i] = mypath+onlyfiles[i]
	
for i in xrange(len(onlyfiles)):
	print "-----------------------"
	print ""
	print onlyfiles[i] + " ..."
	cmd = "file "+onlyfiles[i]
	res = subprocess.check_output(cmd, shell=True)
	if "ELF 32-bit LSB executable" in res:
		cmd = "echo " + onlyfiles[i] + " >> logs"
		os.system(cmd)
		cmd = "python Reassemblablabla_x86.py -f " + onlyfiles[i] +" --align"
		os.system(cmd)
		print ""
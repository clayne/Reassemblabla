#!/usr/bin/python
#-*- coding: utf-8 -*-

from capstone import *
from intelhex import IntelHex
from elftools.elf.elffile import ELFFile
import sys 
import os
import subprocess
import re
from optparse import OptionParser
import binascii 
from pwn import *
from pwnlib.commandline import common


from etc import *
from symbolize import *
from symbolize_lazy import *
from binary2dic import *
from align import *
from linkerhandling import *
from pie_handling import *
from global_variables import *
			
if __name__=="__main__":

	if len(sys.argv) < 2:
		print "[*] Usage :  Reassemblabla_x86_gencompilescript.py <filename>"
		sys.exit(1)

	filename = sys.argv[1]
	LOC = '.'
	CHECKSEC_INFO = pwnlib.elf.elf.ELF(filename, False)

	# Select which script to generate!
	if filename.endswith('.so') and mainaddr == -1: # library
		gen_compilescript_for_sharedlibrary(LOC, filename)

	elif CHECKSEC_INFO.pie == True : # pie binary...
		gen_compilescript_for_piebinary(LOC, filename)


	else: # have main.. and not pie..!
		gen_compilescript(LOC, filename)
	

	onlyfilename = filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print "[ ] input binary    : {}".format(filename)
	print "[ ] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print "-----------------------------------------------------------------"
	print "[+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print ""

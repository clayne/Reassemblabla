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
from SendMSG import *
import sys

def writeline(l, f):
	f.write(l + '\n')

def line2minsec(l):
	_min = float(l[1][:l[1].index('m')])
	_sec = float(l[1][l[1].index('m')+1:l[1].index('s')])
	return _min * 60 + _sec

if __name__=="__main__":
    if len(sys.argv) < 3:
        print "[*] usage : time.py [binaryname] [looptimes]"
        sys.exit(1)
    result = 'timeresult_'+sys.argv[1]
    result = result.replace("/","").replace(".","")
    f = open(result, 'w')

    cmd  = ''
    # cmd += '/bin/bash -c \"time ./encrypted\" 2>&1'
    cmd += '/bin/bash -c \"time ' + sys.argv[1] + '\" 2>&1'
	

    count = 0
    time_real = 0
    time_user = 0
    time_sys = 0

    for i in xrange(int(sys.argv[2])):
        print "Test.. [{}]".format(i)
        try:
            output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            output = e.output

        lines = output.splitlines()

        for l in lines:
            if l == '': continue

            l = l.split("\t")
            if l[0] == 'real':
                _t= line2minsec(l)
                time_real += _t
                writeline(str(i) + ". " + str(l), f)
                writeline("   " + str(time_real), f)
	
	
            elif l[0] == 'user':
                _t= line2minsec(l)
                time_user += _t
                writeline(str(i) + ". " + str(l), f)
                writeline("   " + str(time_user), f)
	
	
            elif l[0] == 'sys':
                _t= line2minsec(l)
                time_sys += _t
                writeline(str(i) + ". " + str(l), f)
                writeline("   " + str(time_sys), f)
	
		writeline("", f)
        if i == 80:
            try:
                SendTelegram("방금 Coreutils Test 80개 돌파...20분쯤 남음")
            except:
                print "Telegram network error"
        elif i == 95:
            try:
                SendTelegram("방금 Coreutils 95개 돌파...5분쯤 남음")
            except:
                print "Telegram network error"

    print ''
    print 'Test Finished!!! Check timeresult. '
    print 'Sending mesage to Telegram_jiwonbot...'
    f.close()
    try:
        SendTelegram("축하! 100개 테스트 완료! 랩가서 화긴ㄱㄱ!")
    except:
        print "Telegram network error"

#!/usr/bin/python
#-*- coding: utf-8 -*-
import requests
import re



def digit_to_ModRM(digit):
	digit = int(digit)
	digit = '{0:03b}'.format(digit)
	ModRM = '11' + digit + '100'
	ModRM = hex(int(ModRM, 2))
	return str(ModRM)

def line_formatting(line):
	line = line.split(' ')

	for i in xrange(len(line)):
		if '#' in line[i]: 
			break
		elif '/' in line[i]:
			digit = line[i][1:]
			line[i] = digit_to_ModRM(digit)
		elif line[i] == 'ib' or line[i] == 'id':
			"Survived...haha"
		elif len(line[i]) > 1:
			line[i] = '0x' + line[i].lower() 
	result = ''
	done = 0
	for i in xrange(len(line)):
		if len(line[i]) > 0:
			if '#' in line[i]:
				done = 1

			if done == 0:
				if line[i].startswith('0x'):
					line[i]  = line[i] + ','
				elif line[i] == 'ib':
					line[i] = '0x11'
				elif line[i] == 'id':
					line[i] = '0x11, 0x11, 0x11, 0x11'
			
			result += line[i] + ' '

	return result 

'''
line = "0F BA /4 ib # BT r/m16, imm8"
print line 
print line_formatting(line)
'''

f = open('result_imm8_or_imm32', 'r')

print ".global main"
print " main:"

while True:
	line = f.readline()
	if not line: break
	line = line[:-1]
	if line.startswith('#'):
		print line
	else:
		print  ' .byte ' + line_formatting(line)

print ""
print ""
print "  ...done!"

'''
인스트럭션 + 11???100 + imm8/imm32
이렇게 구성해서 옆에 붙여놓으면 되겠다. 
'''


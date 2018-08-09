#!/usr/bin/python
#-*- coding: utf-8 -*-

# data section as read/write/no-execute. 그래서 데이터섹션은 디스어셈블안해도 됨. 
from capstone import *
from intelhex import IntelHex
from elftools import *
import sys 
import os
import subprocess
from pwn import *
from pwnlib import *
import re
from optparse import OptionParser
import binascii 

def ishex(str):
	for i in range(len(str)):
		if (str[i]>='0' and str[i]<='9') or (str[i] >= 'a' and str[i] <= 'f'):
			continue
		else:
			return False
	return True
def extract_hex_addr(line):
	# print re.findall(r'\d+', line)
	list1 = re.findall(r'[0-9a-f]+', line)
	list2 = []
	for i in range(0,len(list1)):
		if len(list1[i]) >= 5: # 휴리스틱. 804841b 길이보다 작다면 Drop
			list2.append(int('0x'+list1[i],16))
	return list2

def binarydata2dic(filename): # TODO : 여기에서는 bss, data, rodata 를 담당하도록
	datadic = {}
	retdic = {}
	
	bin = ELF(filename)
	f = open(filename,'r')
	binfile = f.read()
	
	data_section = ['.data','.rodata']
	for i in xrange(len(data_section)):
		s_start = bin.get_section_by_name(data_section[i]).header.sh_addr
		s_offset = bin.get_section_by_name(data_section[i]).header.sh_offset
		s_size = bin.get_section_by_name(data_section[i]).header.sh_size
		s_contents = binfile[s_offset:s_offset+s_size]
		datadic = {} # 초기화
		for j in xrange(s_size):
			addr = s_start + j
			offset = s_offset + j
			datadic[addr] = ['', " .byte 0x" + binascii.b2a_hex(binfile[offset])]
		retdic[data_section[i]] = datadic

	zeroinit_section = ['.bss']
	s_start = bin.get_section_by_name('.bss').header.sh_addr
	s_offset = bin.get_section_by_name('.bss').header.sh_offset
	s_size = bin.get_section_by_name('.bss').header.sh_size
	datadic = {} # 초기화
	for j in xrange(s_size):
		addr = s_start + j
		datadic[addr] = ['', " .byte 0x00"]
	retdic['.bss'] = datadic
	
	return retdic

def binarycode2dic(filename): # TODO : 여기에서는 text섹션만 담당
	cmd = 'objdump -D '+filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() # res.splitlines(True) 하면 엔터까지 포함임. 
	mydic = {} # 딕셔너리 초기화
	section_contents = {}
	section_name = ""
	found = 0
	for i in range(0,len(lines)):
		if len(lines[i]) > 1: # 엔터인줄은무시
			if lines[i].startswith('Disassembly of section'):
				if lines[i].endswith('.text:'):
					section_name = '.text'
					found = 1
					continue
				else:
					found = 0
					continue
			elif found is 1:
				if not lines[i].endswith(':'): # 08048340 <_start>: 같은 줄 제외
					line = re.sub('\s+',' ',lines[i]).strip() # 모든라인의 중복띄어쓰기,탭을 스페이스로바꾸기
					line = parseline(line, "text") # line 은 엔트리 1개짜리 딕셔너리
					line[line.keys()[0]] = ['', line.values()[0]]
					section_contents.update(line) # 딕셔너리에 항목을 추가
	mydic[section_name] = section_contents
	return mydic

# input  : objdump 의 결과라인 한줄
# output : {134520738: ' add $0x8,%al'} <-- 1개짜리 딕셔너리
def parseline(line, type):
	line = re.sub('\s+',' ',line) # 모든라인의 중복띄어쓰기,탭을 스페이스로바꾸기
	l1 = ['','']
	l1[0] = line[:line.index(':')] # 처음나오는 ':' 를 기준으로 왼쪽/오른쪽 나눔
	l1[1] = line[line.index(':')+1:]
	
	# '08048310 <.text>:' 일 경우 예외처리. 아묻따 '00' 하나 우선있는 data section 으로 치자
	if len(l1[1]) is 0:
		l1[0] = l1[0][:l1[0].index(' ')]
		l1[1] = '00'
		type = 'data'
	
	
	addr = int('0x'+l1[0],16) # 시작주소 설정
	addr_enc = addr
	ret_data = {}
	ret_text = {}

	
		
	l1[1] = l1[1].strip() # 주소가 아닌 값 
	l2 = l1[1].split(' ') # .byte 0x30 0x40 이런경우 여러줄에걸쳐서 써주기위해 ' ' 단위로 쪼갬
	is_end = 0
	i = 0
	l_text = ""
	
	while i<len(l2):
		if is_end != 1: # data : 딕셔너리 만들기
			if ishex(l2[i]) and len(l2[i]) == 2: # add 도 헥스데이터로 인식함..
				l_byte = " " + ".byte" + " " + "0x" + l2[i]
				ret_data[addr_enc] = l_byte # 딕셔너리에 쌍 추가. (딕셔너리의 key는 소팅을위해 int로 둠.) 
				addr_enc = addr_enc + 1
			else:
				is_end = 1
				i = i-1
		else: # code : 쪼갠거 걍 다시 주워맞춰서 string 만들기
				l_text += " " + l2[i]
		i = i+1
	ret_text[addr] = l_text # 만든 string을 ret_text[addr] 에 추가
	if type == "data":
			return ret_data
	elif type == "text":
			return ret_text

# input : PC주소
# output : alignment 최대 비트수
# 우서는 align 몇비트까지되는지부터 조사를 해야겠지. 
def get_alignmentbyte(addr, type):
	if type == 'data': # 데이터는 16 byte(SSE instruction),32 byte(AVX instruction), 64(AVX_512, intel의 특정 cpu line에서만 적용됨)
		if addr%64 == 0:
			return 64
		elif addr%32 == 0:
			return 32
		elif addr%16 == 0:
			return 16
	elif type == 'text': # 코드는8, 16
		if addr%16 == 0:
			return 16
		elif addr%8 == 0: # 8byte 가 cache line 최적화에 기여하는지는모르겠지만 align 8도많길래 넣어줌
			return 8
		elif addr%4 == 0:
			return 4
	return 0

def align_text(dics_of_text):
	sorted_keylist = sorted(dics_of_text)
	for i in xrange(len(sorted_keylist)):
		# set line and next line
		line = dics_of_text[sorted_keylist[i]][1]
		if i == len(sorted_keylist)-1:line_next = "" #마지막 요소라면
		else: line_next = dics_of_text[sorted_keylist[i+1]][1]
		
		if "eiz" in line:
			if "eiz" in line_next: 
				dics_of_text[sorted_keylist[i]][1] = "" # eiz포함라인(현재라인)을 없앰
				continue
			else: # 끝까지 갔다. 다음라인에 eiz없음 
				align = get_alignmentbyte(sorted_keylist[i+1],'text')
				if align == 16:
					p2align = ".p2align 4,,15" 
				elif align == 8:
					p2align = ".p2align 3,,7"
				elif align == 4:
					p2align = ".p2align 2,,3"
				else: # 다음라인이 align 이 안맞는다면, p2align을 추가해줄 필요가 없음
					p2align = ""
				dics_of_text[sorted_keylist[i + 1]][1] =  p2align + "\n" + dics_of_text[sorted_keylist[i + 1]][1] 
	return dics_of_text	


def align_data(dics_of_data): # # 데이터섹션에서, 만약에 Symbol이 있는데이터라면 align 맞춰주기
	sorted_keylist = sorted(dics_of_data)
	for i in xrange(len(sorted_keylist)):
			print "a"
	return dics_of_data

	
def save_new_assembly(resdic, filename):
	f = open(filename + "_reassemblable.s",'w')
	f.write(".global main\n")
	f.write("XXX:\n") # 더미위치
	writesection = ['.text','.data','.rodata','.bss']
	for keyname in resdic.keys():
		if keyname in writesection:
			f.write("\n"+".section "+keyname+"\n")
			f.write(".align 16\n") # 모든섹션의 시작주소는 얼라인되게끔
			for key in sorted(resdic[keyname].iterkeys()): #정렬
				for i in range(0,len(resdic[keyname][key])):
					if len(resdic[keyname][key][i]) > 0:
						f.write(resdic[keyname][key][i]+"\n")
	f.close()	
	
	
	
filename = "eiz_ex"

resdic = binarydata2dic(filename)
datardic = binarycode2dic(filename)
resdic.update(datardic)



resdic['.text'] = align_text(resdic['.text'])
resdic['.rodata'] = align_data(resdic['.rodata'])

save_new_assembly(resdic, filename)

'''
for key in sorted(resdic['.data'].iterkeys()):
	print "{} : {}".format(key,resdic['.data'][key])
print "=========="
'''
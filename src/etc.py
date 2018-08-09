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

def ishex(str):
	for i in range(len(str)):
		if (str[i]>='0' and str[i]<='9') or (str[i] >= 'a' and str[i] <= 'f'):
			continue
		else:
			return False
	return True

def extract_hex_addr(line):
	'''
	- extract every hex value from 1 line
	- ex)
		mov    0x20804,%al               --> [20804] --> [133124]
		je     804841b <frame_dummy+0xb> --> [804841b] --> [134513691]
		push   $0x8048540                --> [8048540] --> [134513984]
	'''
	# list1 = re.findall(r'[0-9a-f]+', line) <- 예전코드인데, 어떤 스트링라인 "123 add fdfd qqdq" 에서 123, add,fdfd, d 를 추출하여 리스트로 만드는 코드
	line = line.replace(',',' ').replace('(',' ').replace(')',' ')
	line = re.sub('\s+',' ',line).strip() # duplicate space, tab --> single space
	line = line.split(' ')[1:] # opcode 제거 
	addrlist = []
	
	for i in xrange(len(line)):
		if line[i].startswith('%'): # 레지스터라면.. 그냥 넘겨라
			continue
		else:
			line[i] = line[i].replace('0x','')
			line[i] = line[i].replace('*', '')
			line[i] = line[i].replace('$', '')
			if ishex(line[i]):
				addrlist.append(int('0x'+line[i],16))
	return addrlist

def parseline(line, type): 
	'''
	usage)
		input  : objdump 의 결과라인 한줄
		'text'일 경우 : {1852: ' add %ebx,(%ebx)'} 
		'data'일 경우 : {1852: ' .byte 0x01', 1853: ' .byte 0x1b'} 
	'''
	line = re.sub('\s+',' ',line).strip() # duplicate space, tab --> single space
	addr_bytecode_inst = [line[:line.index(':')], line[line.index(':')+1:]] # 처음나오는 ':' 를 기준으로 왼쪽/오른쪽 나눔
	
	addr = int('0x'+addr_bytecode_inst[0],16) # base address
	addr_encreasing = addr # 초기화
	dic_data = {}
	dic_text = {}
	
	addr_bytecode_inst[1] = addr_bytecode_inst[1].strip() # 주소가 아닌 값 
	l2 = addr_bytecode_inst[1].split(' ') # .byte 0x30 0x40 이런경우 여러줄에걸쳐서 써주기위해 ' ' 단위로 쪼갬
	stop = 0
	i = 0
	
	l_code = ""
	l_data = ""
	l_mach = "#=> " # raw 기계어 코드 필드가 추가되었음
	
	while i<len(l2): 
		if stop != 1: # data
			if ishex(l2[i]) and len(l2[i]) == 2: # add 도 헥스데이터로 인식함..
				l_data = " " + ".byte" + " " + "0x" + l2[i]
				# l_mach += chr(int('0x'+l2[i],16))
				l_mach += '0x' + l2[i] + " "
				dic_data[addr_encreasing] = ['',l_data,'#=> 0x'+l2[i]] # 딕셔너리에 쌍 추가
				addr_encreasing = addr_encreasing + 1
			else:
				stop = 1
				i = i-1
		else: # code 일 경우 위에서 기껏 나눈거 다시 갖다가 붙인다
				l_code += " " + l2[i]
		i = i+1
	dic_text[addr] = ['',l_code,l_mach] # 만든 string을 dic_text[addr] 에 추가
	
	if type == "data":
		return dic_data
	elif type == "text":
		if '(bad)' in l_code: # text 안에 있는 data 라서 disassemble 이 잘 안된경우 걍 데이터로 박아버린다
			return dic_data 
		return dic_text 
	
def findmain(file_name, dics_of_text):
	'''
	entry point 로부터 main 의 주소를 파싱해서 리턴
	
	ex)
		08048310 <.text>:
		8048326:	56                   	push   %esi
		8048327:	68 0b 84 04 08       	push   $0x804840b
		804832c:	e8 bf ff ff ff       	call   80482f0 <__libc_start_main@plt>
		
		에서 0x804840b 를 리턴한다. 
	'''
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
	print "entrypoint is : {}".format(entrypoint)
	findentry = 0
	line = []
	line_before = []
	for key in sorted(dics_of_text.iterkeys()):
		line_before  = line # 이전라인을 백업해두고나서
		line = dics_of_text[key] # 새로운 value를 받아들인다
		if findentry is 1:
			if "__libc_start_main" in line[1]: # line = ['','pop ret 어쩌구']
				break # 그만찾으셈
			else:
				continue # 아래라인으로 내려가지않도록
		if key == entrypoint: 
			findentry = 1
	'''
	$ 으로시작하도록 push하니깐 그냥그값만 긁어온다
	8048357:	68 3b 84 04 08       	push   $0x804843b
	804835c:	e8 bf ff ff ff       	call   8048320 <__libc_start_main@plt>
	'''
	l = line_before[1].split(' ')
	for i in range(0,len(l)):
		if l[i].startswith('$'):
			return int(l[i][1:],16)

def findenytypoint(file_name):
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
	print "entrypoint is : {}".format(entrypoint)
	return entrypoint
	
def remove_brackets(dics_of_text):
	'''
	
	# TODO 
	ex) 
	   call  1b54b <main@@Base+0xc0ab>  --> call   1b54b
	'''
	for i in range(0,len(dics_of_text)):
		try:
			line = dics_of_text.values()[i][1]
			index1 = line.index('<')
			index2 = line.index('>')
			dics_of_text.values()[i][1] = line[:index1] + line[index2+1:]
		except:
			"dummy"

def get_shtable(filename): # 섹션들에 대한 정보들을 가지고있는 테이블
	SHTABLE = {}
	f = open(filename,'rb')
	elffile = ELFFile(f)
	for nsec, section in enumerate(elffile.iter_sections()):
		entry = {} # initializaion
		entry['sh_type']      = section['sh_type']
		entry['sh_addr']      = section['sh_addr']
		entry['sh_offset']    = section['sh_offset']
		entry['sh_size']      = section['sh_size']
		entry['sh_entsize']   = section['sh_entsize']
		entry['sh_flags']     = section['sh_flags']
		entry['sh_link']      = section['sh_link']
		entry['sh_info']      = section['sh_info']
		entry['sh_addralign'] = section['sh_addralign']
		SHTABLE[section.name]  = entry
	f.close()
	return SHTABLE
	
def gen_assemblescript(filename):
	'''
	laura@ubuntu:/mnt/hgfs/VM_Shared/reassemblablabla/src$ ldd lcrypto_ex
		linux-gate.so.1 =>  (0xf774f000)
		libcrypto.so.1.0.0 => /lib/i386-linux-gnu/libcrypto.so.1.0.0 (0xf7545000)
		libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf738f000)
		libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xf738a000)
		/lib/ld-linux.so.2 (0x56623000)
	'''
	
	
	'''
	as -o dash_reassemblable.o dash_reassemblable.s
	ld -o dash_reassemblable -dynamic-linker /lib/ld-linux.so.2  /usr/lib/i386-linux-gnu/crti.o -lc dash_reassemblable.o /usr/lib/i386-linux-gnu/crtn.o
	'''
	onlyfilename = filename.split('/')[-1]
	cmd  = ""
	cmd += "as -o "
	cmd += onlyfilename + "_reassemblable.o "
	cmd += onlyfilename + "_reassemblable.s"
	cmd += "\n"
	cmd += "ld -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += "-dynamic-linker /lib/ld-linux.so.2  /usr/lib/i386-linux-gnu/crti.o "
	cmd += "-lc "
	cmd += onlyfilename + "_reassemblable.o "
	cmd += "/usr/lib/i386-linux-gnu/crtn.o"
	
	
	f = open(onlyfilename + "_assemble.sh", 'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + onlyfilename + "_assemble.sh"
	os.system(cmd)
	
def gen_compilescript(filename):
	'''
	laura@ubuntu:/mnt/hgfs/VM_Shared/reassemblablabla/src$ ldd lcrypto_ex
		linux-gate.so.1 =>  (0xf774f000)
		libcrypto.so.1.0.0 => /lib/i386-linux-gnu/libcrypto.so.1.0.0 (0xf7545000)
		libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf738f000)
		libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xf738a000)
		/lib/ld-linux.so.2 (0x56623000)
	'''

	cmd = 'ldd ' + filename
	res = subprocess.check_output(cmd, shell=True)

	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "
	lines = res.splitlines()
	for i in xrange(len(lines)):
		if "=>" in lines[i]:
			cmd += lines[i].split(' ')[2]
			cmd += " "

	f = open(onlyfilename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + onlyfilename + "_compile.sh"
	os.system(cmd)

def gen_assemblyfile(resdic, filename):
	onlyfilename = filename.split('/')[-1] # filename = "/bin/aa/aaaa" 에서 aaaa 민 추출한다
	f = open(onlyfilename + "_reassemblable.s",'w')
	# f.write(".global main\n")
	f.write(".global _start\n")
	f.write("XXX:\n") # 더미위치
	writesection = ['.text','.data','.rodata','.bss','.init']
	for sectionName in resdic.keys():
		if sectionName in writesection:
			f.write("\n"+".section "+sectionName+"\n")
			f.write(".align 16\n") # 모든섹션의 시작주소는 얼라인되게끔
			for address in sorted(resdic[sectionName].iterkeys()): #정렬
				for i in range(0,len(resdic[sectionName][address])): # TODO
				#for i in xrange(2):
					if len(resdic[sectionName][address][i]) > 0:
						f.write(resdic[sectionName][address][i]+"\n")
	f.close()
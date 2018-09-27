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
from global_variables import *

def logging(mystr):
	print " [*] " + str(mystr)

def get_soname(filename):
	try:
		out = subprocess.check_output(['objdump', '-p', filename])
	except:
		return ''
	else:
		result = re.search('^\s+SONAME\s+(.+)$',out,re.MULTILINE)
		if result:
			return result.group(1)
		else:
			return ''

def extract_register(line):
	reglist = []
	while '%' in line: 
		line = line[line.index('%')+1:]
		reglist.append(line[:3])
	return reglist

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
		elif len(line[i]) == 0: # 쓸모없는거라면 넘겨라
			continue

		else:
			line[i] = line[i].replace('0x','')
			line[i] = line[i].replace('*', '')
			line[i] = line[i].replace('$', '') 
			if line[i] == '': # 전처리 후 나온 line 이 '' 이라면 패스 
				continue 
			if line[i][0] == '-': # 음수라면
				if len(line[i])>1 and ishex(line[i][1:]): # 그게 헥스값이라면 
					addrlist.append(-int('0x'+line[i][1:],16))	

			else: # 양수라면 
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
				dic_data[addr_encreasing] = ['',
											l_data,
											'#=> ' + 'ADDR:' + str(hex(addr_encreasing)) + ' BYTE:'+ '0x'+l2[i],
											'',
											''
											] # 딕셔너리에 쌍 추가
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

def findmain(file_name, resdic, __libc_start_main_addr, CHECKSEC_INFO):
	# call __libc_start_main 이 아니라, call 0x8108213 (0x8108213 주소의 심볼 : __libc_start_main) 이더라도 main을 리턴할수 있게만 하면되지.
	'''
	entry point 로부터 main 의 주소를 파싱해서 리턴
	
	ex)
		08048310 <.text>:
		8048326:	56                   	push   %esi
		8048327:	68 0b 84 04 08       	push   $0x804840b
		804832c:	e8 bf ff ff ff       	call   80482f0 <__libc_start_main@plt>
		
		에서 0x804840b 를 리턴한다. 
	'''
	dics_of_text = resdic['.text']
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
	i = 0
	main = -1 # main 이 없다면 -1 리턴.. 
	befoline = 'dummy line 000'

	for addr in sorted(dics_of_text.iterkeys()):
		line = dics_of_text[addr][1]
		if len(extract_hex_addr(line)) > 0:
			suspect = extract_hex_addr(line)[0]
			if suspect == __libc_start_main_addr:
				main = extract_hex_addr(befoline)[0]
				break
		befoline = line

	# pie 바이너리에는 .got  섹션 안에 main의 위치가 있었다. 
	# 그래서 __libc_start_main 의 바로 위칸에서 원래는 push $main 을 해야할 때,
	# push -0xc(%ebx) 를 하는 거시였다...
	# 그러므로 나는 휴리스틱하게 -0xc(_GLOBAL_OFFSET_TABLE_) 에 있는 주소값을 읽어다가 리턴을 해줄 거시다. 
	if CHECKSEC_INFO.relro == 'Full':
		_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got'].keys())[0]
	else:
		_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got.plt'].keys())[0]



	if CHECKSEC_INFO.pie == True:
		mainaddr_is_in = _GLOBAL_OFFSET_TABLE_ + main
		print "main *********** : {}".format(hex(mainaddr_is_in))
		for addr in sorted(resdic['.got'].keys()):
			if mainaddr_is_in == addr:
				main  = ''
				main += resdic['.got'][mainaddr_is_in+3][1]
				main += resdic['.got'][mainaddr_is_in+2][1]
				main += resdic['.got'][mainaddr_is_in+1][1]
				main += resdic['.got'][mainaddr_is_in+0][1]
				main = main.replace(' .byte 0x','')
				main = int('0x' + main,16)

	return main

def findstart(file_name):
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
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

def setsymbolnamefor_GLOB_DAT(T_glob):
	for key in T_glob.keys():
		if T_glob[key] == '__gmon_start__': # __gmon_start__ 는 일반바이너리에도 있는 GLOB_DAT이다. 근데 ebx로 접근하지도 않을뿐더러 사용하려고 접근하면 어셈블도 안되므로 우선은 빼줌. 
											# 이와 비슷한 걸로는 _ITM_deregisterTMClone, _Jv_RegisterClasses 등이 있다. 
											# 이들의 공통점으로는 .rel.dyn 에서 심볼이름의 뒤에 @GLIBC 가 붙지 않는다는 점이다...
											# COMMENT: 하나의 휴리스틱 룰을 더 추가. R_386_GLOB_DAT 중에서 뒤에 @GLIBC가 붙지 않는 데이터는... 조또쓸데없는거시다...
			del T_glob[key]
		else:
			T_glob[key] = T_glob[key] + '@GOT(%ebx)'


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

def gen_assemblescript(LOC, filename):
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

	cmd = 'ldd ' + filename
	res = subprocess.check_output(cmd, shell=True)

	onlyfilename = filename.split('/')[-1]
	cmd  = ""
	cmd += "as -g -o " 
	cmd += onlyfilename + "_reassemblable.o "
	cmd += onlyfilename + "_reassemblable.s"
	cmd += "\n"
	cmd += "ld --entry=MYSTART -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += "-dynamic-linker /lib/ld-linux.so.2 "
	cmd += "-lc "

	libraries = res.splitlines() # 잠깐 라이브버리좀 붙이고 가겠슴. 
	for i in xrange(len(libraries)):
		if "=>" in libraries[i]:
			cmd += libraries[i].split(' ')[2]
			cmd += " "	

	cmd += onlyfilename + "_reassemblable.o "
	cmd += crts
	
	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh", 'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_assemblescript_for_piebinary(LOC, filename):
	cmd = 'ldd ' + filename
	res = subprocess.check_output(cmd, shell=True)

	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc -g -pie -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "
	lines = res.splitlines()
	for i in xrange(len(lines)):
		if "=>" in lines[i]:
			cmd += lines[i].split(' ')[2]
			cmd += " "
	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_assemblescript_for_sharedlibrary(LOC, filename):
	cmd = 'ldd ' + filename
	res = subprocess.check_output(cmd, shell=True)

	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc -g -fPIC -shared -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "
	lines = res.splitlines()
	for i in xrange(len(lines)):
		if "=>" in lines[i]:
			cmd += lines[i].split(' ')[2]
			cmd += " "
	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_compilescript(LOC, filename):
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
	cmd += "gcc -g -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "
	lines = res.splitlines()
	for i in xrange(len(lines)):
		if "=>" in lines[i]:
			cmd += lines[i].split(' ')[2]
			cmd += " "
	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_assemblyfile(LOC, resdic, filename, symtab, comment):
	onlyfilename = filename.split('/')[-1] # filename = "/bin/aa/aaaa" 에서 aaaa 민 추출한다

	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_reassemblable.s",'w')


	f.write(".global main\n")
	f.write(".global _start\n")
	f.write("XXX:\n") # 더미위치
	f.write(" ret\n") # 더미위치로의 점프를 위한 더미리턴 



	for sectionName in resdic.keys():
		if sectionName in AllSections_WRITE:
			SectionThatLoaderAutomaticallyAdds_code = ['.init','.fini', '.ctors', '.dtors']
			SectionThatLoaderAutomaticallyAdds_data = ['.init_array','.fini_array','.got', '.jcr', '.data1', '.rodata1', '.tbss', '.tdata']
			if sectionName in SectionThatLoaderAutomaticallyAdds_code:
				f.write("\n" + ".section " + ".text" + "\n")
			elif sectionName in SectionThatLoaderAutomaticallyAdds_data:
				f.write("\n" + ".section " + ".data" + "\n")
			else:
				f.write("\n"+".section "+sectionName+"\n")


			f.write(".align 16\n") # 모든섹션의 시작주소는 얼라인되게끔 
			if comment == 1: 
				#RANGES = len(resdic['.text'][resdic['.text'].keys()[0]]) # 사실상 걍4인데, array가 더추가될수도있응게..
				RANGES = 3 #3이면 충분할듯. 왜냐면 아래 PIE관련정보는 굳이 없어도되잖아? 어셈블도 안될텐데.
			else:
				RANGES = 2
			for address in sorted(resdic[sectionName].iterkeys()): #정렬
				#for i in range(0,len(resdic[sectionName][address])): # 주석까지 프린트 하려면 활성화 해주길..
				for i in xrange(RANGES):
					if len(resdic[sectionName][address][i]) > 0: # 그냥 엔터만 아니면 됨 
						f.write(resdic[sectionName][address][i]+"\n")
	f.close()
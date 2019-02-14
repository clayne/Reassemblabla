#!/usr/bin/python
#-*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
import os
import subprocess
import re
import sys 

from global_variables import *



def one_operand_instruction(DISASM):
	if '#' in DISASM:                                   # 주석 제거
		DISASM = DISASM[:DISASM.index('#')]  
	if ',' not in DISASM: return True                   # call %eax
	else:                                               # call 0x12(%eax, %ebx, 2)
		if '(' in DISASM and ')' in DISASM:
			i1 = DISASM.index('(')
			i2 = DISASM.index(')')
			DISASM = DISASM.replace(DISASM[i1:i2 + 1],'')
			if ',' not in DISASM:
				return True
	return False                                       # default. ex) mov $0x12, 0x12(%eax, %ebx, 4)

def unsigned2signed(integervalue): 
	if integervalue > 0xffffffff: # 8byte long
		if integervalue > 0x7fffffffffffffff:
			ret = integervalue ^ 0xffffffffffffffff
			ret = ret + 1
			ret = (-1) * ret
			return ret
		else:
			return integervalue		
	else:
		if integervalue > 0x7fffffff:
			ret = integervalue ^ 0xffffffff
			ret = ret + 1
			ret = (-1) * ret
			return ret
		else:
			return integervalue

def signed2unsigned(integervalue):
	if integervalue < 0:
		if integervalue < (-1) * 0x7fffffff: # 8byte의 int이다.
			integervalue = (-1) * integervalue
			integervalue = integervalue - 1
			ret = integervalue ^ 0xffffffffffffffff
			return ret
		else: # 일반적인 4byte의 int이다.
			integervalue = (-1) * integervalue
			integervalue = integervalue - 1
			ret = integervalue ^ 0xffffffff
			return ret
	else:
		return integervalue

def instruction_div(edx, eax, divisor):
	# 나누어지는수는 long(8byte)로서 edx + eax 를 조립해서 만든다. 
	eax = '{0:x}'.format(eax).zfill(8)
	edx = '{0:x}'.format(edx).zfill(8)
	divident = int('0x' + edx + eax, 16)

	quotient = divident / divisor
	remainder = divident % divisor
	return quotient, remainder

def instruction_idiv(edx, eax, divisor):
	# 나누어지는수는 long(8byte)로서 edx + eax 를 조립해서 만든다. 
	eax = '{0:x}'.format(eax).zfill(8)
	edx = '{0:x}'.format(edx).zfill(8)
	divident = int('0x' + edx + eax, 16)

	divident_signed = unsigned2signed(divident)
	divisor_signed  = unsigned2signed(divisor)

	quotient = divident_signed / divisor_signed
	remainder = divident_signed % divisor_signed

	return signed2unsigned(quotient), signed2unsigned(remainder)


def instruction_mul(v1, v2):
	res = v1 * v2
	res = hex(res)
	print res
	res = res.replace('L','').replace('0x','')
	print len(res)
	if len(res) > 8:
		rightpart = '0x' + res[-8:]
		leftpart  = '0x' + res[:-8]
	else:
		rightpart = '0x' + res
		leftpart  = '0x' + '0'

	return int(leftpart, 16), int(rightpart, 16)

def instruction_imul(v1, v2):
	v1 = unsigned2signed(v1)
	v2 = unsigned2signed(v2)
	res = v1*v2
	if res >= 0:
		res = hex(res)
	elif res < 0:
		res = hex(signed2unsigned(res))
	print "res : {}".format(res)
	res = res.replace('L','').replace('0x','')
	print "res : {}".format(res)
	if len(res) > 8:
			rightpart = '0x' + res[-8:]
			leftpart  = '0x' + res[:-8]
	else:
		rightpart = '0x' + res
		leftpart  = '0x' + '0'
	
	return int(leftpart, 16), int(rightpart, 16)

def bitflip_the_index(idx, register_value):
	idx = idx%32 # 이제 인덱스가 나왓다. 
	idx = 31-idx # array 는 젤위가 인덱스0이니깐... 
	BIN_register_value = str('{0:32b}'.format(register_value)) # 길이 32짜리 2진수값으로 변환
	BIN_register_value = BIN_register_value.replace(' ','0') # 맨앞은 space로 채워지는 경향이있는데 걍 0으로 바꿈
	if BIN_register_value[idx] == '1':
		BIN_register_value = BIN_register_value[0:idx] + '0' + BIN_register_value[idx+1:]
	elif BIN_register_value[idx] == '0':
		BIN_register_value = BIN_register_value[0:idx] + '1' + BIN_register_value[idx+1:]
	return int(BIN_register_value, 2)%0x100000000

def bitset_the_index(idx, register_value):
	idx = idx%32 # 이제 인덱스가 나왓다. 
	idx = 31-idx # array 는 젤위가 인덱스0이니깐... 
	BIN_register_value = str('{0:32b}'.format(register_value)) # 길이 32짜리 2진수값으로 변환 ' '로채워져 '0'이아니라.
	BIN_register_value = BIN_register_value.replace(' ','0')
	if BIN_register_value[idx] == '1':
		'nothing to do'
	elif BIN_register_value[idx] == '0':
		BIN_register_value = BIN_register_value[0:idx] + '1' + BIN_register_value[idx+1:]
	return int(BIN_register_value, 2)%0x100000000

def bitreset_the_index(idx, register_value):
	idx = idx%32 # 이제 인덱스가 나왓다. 
	idx = 31-idx # array 는 젤위가 인덱스0이니깐... 
	BIN_register_value = str('{0:32b}'.format(register_value)) # 길이 32짜리 2진수값으로 변환
	BIN_register_value = BIN_register_value.replace(' ','0') # 맨앞은 space로 채워지는 경향이있는데 걍 0으로 바꿈
	if BIN_register_value[idx] == '1':
		BIN_register_value = BIN_register_value[0:idx] + '0' + BIN_register_value[idx+1:]
	elif BIN_register_value[idx] == '0':
		'nothing to do'
	return int(BIN_register_value, 2)%0x100000000

def bitrotate_the_index(idx, register_value, direction):
	idx = idx%32
	BIN_register_value = str('{0:32b}'.format(register_value)) 
	BIN_register_value = BIN_register_value.replace(' ','0')
	if direction == 'right':
		BIN_register_value =  BIN_register_value[(-1)*idx:] + BIN_register_value[:(-1)*idx]
	elif direction == 'left':
		BIN_register_value =  BIN_register_value[idx:] + BIN_register_value[:idx]
	return int(BIN_register_value, 2)%0x100000000

def bitshift_the_index(idx, register_value, direction):
	idx = idx%32
	BIN_register_value = str('{0:32b}'.format(register_value)) 
	BIN_register_value = BIN_register_value.replace(' ','0')
	if direction == 'right':
		BIN_register_value =  '0'*idx + BIN_register_value[:(-1)*idx]
	elif direction == 'left':
		BIN_register_value =  BIN_register_value[idx:] + '0'*idx
	return int(BIN_register_value, 2)%0x100000000

def bitshift_arithmetic_the_index(idx, register_value, direction):
	# 비트들을 shift하되, most lowest bit/most highest bit 는 원본value의 값을 고대로 유지한다. 즉 10000000 을 3만큼 shift arithmetic right하면 11110000 이다 
	idx = idx%32
	BIN_register_value = str('{0:32b}'.format(register_value)) 
	BIN_register_value = BIN_register_value.replace(' ','0')
	if direction == 'right':
		mosthighbit = BIN_register_value[0]
		BIN_register_value =  mosthighbit*idx + BIN_register_value[:(-1)*idx]
	elif direction == 'left':
		mostlowbit = BIN_register_value[-1]
		BIN_register_value =  BIN_register_value[idx:] + mostlowbit*idx
	return int(BIN_register_value, 2)%0x100000000

def bitscan(register_value, direction):
	register_value = register_value%0x100000000
	BIN_register_value = str('{0:32b}'.format(register_value)) 
	BIN_register_value = BIN_register_value.replace(' ','0')
	if direction == 'right':
		for idx in xrange(32):
			if BIN_register_value[idx] == '1':
				return 31-idx # 스트링 인덱스는 거꾸로 간다
	elif direction == 'left':
		for idx in xrange(32):
			idx = 31-idx
			if BIN_register_value[idx] == '1':
				return 31-idx
	return -1

def there_is_memory_reference(line):
	if '#' in line:
		line = line[:line.index('#')]
	if '(' in line and ')' in line:
		return True
	else:
		return False


def list_insert(position, list1, list2):
	return list1[:position] + list2 + list1[position:]

def pickpick_idx_of_orig_disasm(theList):
	origList = []
	for i in xrange(len(theList)):
		if '#+++++' in theList[i]: 
			continue
		else: 
			origList.append(i)
	return origList # COMMENT: 모든 라인이 디스어셈블러가 추가해준 라인일 경우 빈 리스트가 리턴된다.

def logging(mystr):
	print " [*] " + str(mystr)

def ldd(filename):
	cmd = 'ldd ' + filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() # 잠깐 라이브버리좀 붙이고 가겠슴. 
	libraries = []
	for l in lines:
		if '(' in l and ')' in l:
			l = l.replace(l[l.index('('):l.index(')')+1], '') # (0xb7dae000) 같은 쓸데없는 정보 없애기

		if 'linux-gate.so' in l: # 파일시스템에 없는 가상의 라이브러리는 제외
			continue
		elif 'ld-linux.so' in l: # 로더는 자동으로 붙으니 제외
			continue
		elif 'not found' in l: # 전체경로를 못찾은 라이브러리. 즉, 인풋바이너리와 같은 경로에 있는 라이브러리라던가..
			# =>에서 왼쪽을 파싱
			libraries.append(l.split('=>')[0].strip())
		else:
			# =>에서 오른쪽을 파싱
			libraries.append(l.split('=>')[1].strip())
	return libraries

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


def classificate_registers(line):
	ret = {'REFERENCE_REGISTER':[], 'ORDINARY_REGISTER':[]}
	i1 = i2 = -1
	if ('(') in line: # () 는 나올거면 단 한번만 출현함 
		i1 = line.index('(') 
		i2 = line.index(')')

	if i1 == -1:
		REGREF_ARGUMENTS = ''
	else:
		REGREF_ARGUMENTS = line[i1:i2 + 1]
		line = line.replace(REGREF_ARGUMENTS,'')

	ret['REFERENCE_REGISTER'] = extract_register(REGREF_ARGUMENTS)
	ret['ORDINARY_REGISTER']  = extract_register(line)
	return ret


def ishex(str):
	for i in range(len(str)):
		if (str[i]>='0' and str[i]<='9') or (str[i] >= 'a' and str[i] <= 'f'):
			continue
		else:
			return False
	return True


def extract_hex_values(line):
	'''
	- extract every hex value from 1 line
	- ex)
		mov    0x20804,%al               --> [20804] --> [133124]
		je     804841b <frame_dummy+0xb> --> [804841b] --> [134513691]
		push   $0x8048540                --> [8048540] --> [134513984]
	'''
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


def findmain(file_name, resdic, __libc_start_main_addr, CHECKSEC_INFO):
	'''
	entry point 로부터 main 의 주소를 파싱해서 리턴 (휴리스틱)
	
	ex)
		08048310 <.text>:
		8048326:	56                   	push   %esi
		8048327:	68 0b 84 04 08       	push   $0x804840b 
		804832c:	e8 bf ff ff ff       	call   80482f0 <__libc_start_main@plt>
		
		에서 0x804840b 를 리턴한다. 
	'''
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
	i = 0
	main = -1 # main 이 없다면 -1 리턴.. 
	befoline = 'dummy line 000'

	for ADDR in sorted(resdic['.text'].iterkeys()):
		orig_i_list = pickpick_idx_of_orig_disasm(resdic['.text'][ADDR][1])
		for orig_i in orig_i_list:
			line = resdic['.text'][ADDR][1][orig_i]
			if len(extract_hex_values(line)) > 0:
				suspect = extract_hex_values(line)[0] # __libc_start_main_addr 주소가 언급되었나?
				if suspect == __libc_start_main_addr:
					main = extract_hex_values(befoline)[0]
					break
			befoline = line
		if main != -1:
			break
	if CHECKSEC_INFO.relro == 'Full':
		_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got'].keys())[0]
	else:
		_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got.plt'].keys())[0]

	if CHECKSEC_INFO.pie == True: # pie 바이너리라면 libc_start_main 전에 pushl -0xc(%ebx)를 한다. got의 이주소에 main이 들어있다. 
		mainaddr_is_in = _GLOBAL_OFFSET_TABLE_ + main
		for ADDR in sorted(resdic['.got'].keys()):
			if mainaddr_is_in == ADDR:
				main  = ''
				main += resdic['.got'][mainaddr_is_in+3][1][0]
				main += resdic['.got'][mainaddr_is_in+2][1][0]
				main += resdic['.got'][mainaddr_is_in+1][1][0]
				main += resdic['.got'][mainaddr_is_in+0][1][0]
				main = main.replace(' .byte 0x','')
				main = int('0x' + main,16)
	return main


def findstart(file_name):
	entrypoint = ELFFile(open(file_name,'rb')).header.e_entry
	return entrypoint

def concat_symbolname_to_TABLE(T, concat):
	for key in T.keys():
		T[key] = T[key] + concat

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

	libraries = ldd(filename)
	for l in libraries:
		cmd += l
		cmd += " "	

	cmd += onlyfilename + "_reassemblable.o "
	cmd += crts
	
	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh", 'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_compilescript_for_piebinary(LOC, filename):
	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc -g -pie -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "

	libraries = ldd(filename)
	for l in libraries:
		cmd += l
		cmd += " "	

	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_compilescript_for_sharedlibrary(LOC, filename):

	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc -g -fPIC -shared -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "

	libraries = ldd(filename)
	for l in libraries:
		cmd += l
		cmd += " "	

	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_compilescript(LOC, filename, testingcrashhandler):
	onlyfilename = filename.split('/')[-1]	
	cmd  = ""
	cmd += "gcc "
	if testingcrashhandler is True:
		# cmd += "-Wl,--section-start=.dynsym=0x09000000 " #TODO: 이게 정석임. 이걸 어떻게든 고쳐서쓰는게 정석인데, 그냥 지금은 귀찮아서 pie옵션으로 땜빵하는 중. 
		cmd += " -pie "

	cmd += "-g -o "
	cmd += onlyfilename + "_reassemblable "
	cmd += onlyfilename + "_reassemblable.s "
	cmd += "-m32 "

	libraries = ldd(filename)
	for l in libraries:
		cmd += l
		cmd += " "	

	saved_filename = LOC + '/' + onlyfilename

	f = open(saved_filename + "_compile.sh",'w')
	f.write(cmd)
	f.close()
	
	cmd = "chmod +x " + saved_filename + "_compile.sh"
	os.system(cmd)

def gen_assemblyfile(LOC, resdic, filename, CHECKSEC_INFO, comment, SYMTAB):

	onlyfilename = filename.split('/')[-1] # filename = "/bin/aa/aaaa" 에서 aaaa 민 추출한다
	saved_filename = LOC + '/' + onlyfilename
	f = open(saved_filename + "_reassemblable.s",'w')

	f.write(".global main\n")
	f.write(".global _start\n")
	f.write("XXX:\n") # 더미위치
	f.write(" ret\n") # 더미위치로의 점프를 위한 더미리턴 

	for sectionName in resdic.keys():
		if sectionName in AllSections_WRITE:
			if sectionName not in DoNotWriteThisSection:
				# 섹션이름 쓰기
				if sectionName in TreatThisSection2TEXT:
					f.write("\n" + ".section " + ".text" + "\n")
					f.write("\n" + "# Actually, here was .section " + sectionName + "\n")
				elif sectionName in TreatThisSection2DATA:
					f.write("\n" + ".section " + ".data" + "\n")
					f.write("\n" + "# Actually, here was .section " + sectionName + "\n")
				else:
					f.write("\n"+".section "+sectionName+"\n")
				
				# 섹션의 align 은 디폴트로 16. (init_array, fini_array 는 제외)
				if sectionName == '.init_array' or sectionName == '.fini_array':
					'패스. .init_array, .fini_array는 align되면 안됨. 왜냐하면 저장된 주소레퍼런스값을 순회할때 +4+4... 으로 포인터값을 늘려나가는데, 00000000 패딩이 추가된다면 그곳을 실행하게되기 때문이다.'
				else:
					f.write(".align 16\n") # 모든섹션의 시작주소는 얼라인되게끔 

				# 어셈블리 생성!
				if comment is True: 
					RANGES = 3 # 3이면 충분할듯. TODO: 이부분이 가독성 안좋음. 나중에 갈아엎고 고칠 것
				else:
					RANGES = 2

				for ADDR in sorted(resdic[sectionName].iterkeys()): # 정렬
					if ADDR in SYMTAB:
						f.write('# '  + sectionName[1:] + ' @ ' + hex(ADDR) + "\n")	
					for i in xrange(RANGES): 
						if len(resdic[sectionName][ADDR][i]) > 0: # 그냥 엔터만 아니면 됨 
							if i == 1: 	# 출력물:resdic[sectionName][ADDR][1](디스어셈블리) 
								for j in xrange(len(resdic[sectionName][ADDR][i])):
									f.write(resdic[sectionName][ADDR][i][j]+"\n")	
							else: 		# 출력물:resdic[sectionName][ADDR][0](심볼이름), resdic[sectionName][ADDR][2](주석)
								f.write(resdic[sectionName][ADDR][i]+"\n")
	f.close()
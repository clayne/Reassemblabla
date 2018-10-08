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
from binary2dic import *
from align import *
from linkerhandling import *
from pie_handling import *
from global_variables import *
			
if __name__=="__main__":

	usage = "usage: %prog -f [FILE] <OPTIONS>"
	parser = OptionParser(usage=usage, version="%prog 1.0")
	parser.add_option("-f", "--filename", dest="filename", help="denote binary file")
	parser.add_option("-a", "--align", dest="align", help="align datas in data section", action="store_true")
	parser.add_option("-c", "--comment", dest="comment", help="add bytepattern info as a comment", action="store_true")
	parser.add_option("-d", "--datainsert", dest="datainsert", help="insert datas to data section", action="store_true")
	parser.add_option("-l", "--location", dest="location", help="location to save result files")
	

	parser.set_defaults(verbose=True)
	(options, args) = parser.parse_args()

	print ""
	print ""
	
	if options.filename is None:
		print "Usage : python Reassemblabla.py -f [BINARY] <OPTION>"
		print "     --align   : lign datas in data section" 
		print "     --insert  : insert datas to data section" 
		print "     --comment : add bytepattern info as a comment" 
		print "     --location : denote location(directory) to save the result files" 
		sys.exit(0)

	if options.location is None:
		LOC = '.'
		print "[*] Result files will be saved at default location! ---> {}".format(LOC)

	else:
		LOC = options.location
		print "[*] Result files will be saved at.. ---> {}".format(LOC)
		if not os.path.exists(LOC): 
			print "[!] Designated location does not exist!"
			sys.exit(0)


	SHTABLE = get_shtable(options.filename)

	# initialize resdic
	resdic = binarycode2dic(options.filename, SHTABLE)
	resdic_data = binarydata2dic(options.filename)
	resdic.update(resdic_data)
	CHECKSEC_INFO = pwnlib.elf.elf.ELF(options.filename, False)





	# ==테이블 셋팅== : .dynsym 은 처리안해줘도 된다. 왜냐하면 .rel.dyn과 .rel.plt에 포함되어있기 때문.
	T_rel = get_relocation_tables(options.filename)

	eliminate_weird_GLOB_DAT(T_rel['R_386_GLOB_DAT'])

	# pie바이너리를 위한 테이블수정이 살짝 있겠습니다...
	if CHECKSEC_INFO.pie == True:
		concat_symbolname_to_TABLE(T_rel['R_386_GLOB_DAT'], '@GOT(REGISTER_WHO)')
		concat_symbolname_to_TABLE(T_rel['R_386_JUMP_SLOT'], '@PLT')

	T_plt2name = got2name_to_plt2name(T_rel['R_386_JUMP_SLOT'], CHECKSEC_INFO, resdic)# T_got2name 을 T_plt2name으로 바꾼다.



	# ==심볼이름 레이블링==
	# 레이블링 순서는 휘발성이강하고(weak) 국소적인 이름부터한다. 1. Relocation section table 2. Weak symbol 3. Global symbol
	dynamic_symbol_labeling(resdic, T_plt2name) 
	dynamic_symbol_labeling(resdic, T_rel['R_386_GLOB_DAT']) 
	dynamic_symbol_labeling(resdic, T_rel['R_386_COPY']) 
	pltsection_sanitize(resdic) # 이름없는 got로향하는 무의미한 plt 들에 XXX 라는 더미이름을 하사해 주겠노라




	# main 을 labeling 하기 위한 20줄에 걸친 몸부림..
	__libc_start_main_addr = -1
	for addr in T_plt2name.keys():
		if T_plt2name[addr] == '__libc_start_main':
			__libc_start_main_addr = addr
	if __libc_start_main_addr == -1:
		mainaddr = -1
	else:
		mainaddr = findmain(options.filename, resdic, __libc_start_main_addr, CHECKSEC_INFO)
	startaddr = findstart(options.filename)

	if mainaddr == -1: 
		resdic['.text'][startaddr][0] = "MYSYM_ENTRY:" # "_start:" 가 들어가면, 왠진모르겠지만 라이브러리의 call _start 에서 이상한 곳을 CALL 하게된다. 
	else: 
		resdic['.text'][mainaddr][0] = "main:"


	# 심볼라이즈 전에 brackets를 다 제거해야징
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			remove_brackets(resdic[SectionName]) 
	

	# get_pc_thunk 같은게 있을경우 이거 심볼라이즈
	pcthunk_reglist = getpcthunk_labeling(resdic)

	# ===일반 address 심볼라이즈===
	symbolize_textsection(resdic)
	symbolize_datasection(resdic)


	# ===calculated address 심볼라이즈===
	PIE_set_getpcthunk_loc(resdic) # get_pc_thunk 를 호출하는 라인의 EIP를 resdic[name][3]에다가 쓴다. 주의: get_pc_thunk를 호출하는지안하는지는 symbolize_textsection 을 거친후에야 알수있음
	PIE_calculated_addr_symbolize(resdic)
	

	# ===남은것들중 GOT베이스로다가 데이터에접근하는놈들 심볼라이즈===
	PIE_DynamicSymbolize_GOTbasedpointer(pcthunk_reglist, resdic,CHECKSEC_INFO)

	# ===남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다===
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_remove_callweirdaddress(resdic[SectionName])

	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data(resdic[SectionName])
	


	# ===마지막으로 call stderror@GOT(REGISTER_WHO)로 blank로 심볼리제이션된거 resdic[3]을 참조해서 레지스터자리채워주기===
	fill_blanked_symbolname_toward_GOTSECTION(resdic)

	# ===data sections 에 아직 남아있는 dynamic symbol 을 없애버린다. (심볼이 붙어있음 == 이름이 의미가 있음 == 링커가 알아서해주는 심볼임 == 없애도댐)===
	not_global_symbolize_datasection(resdic)

	# ===getpcthunk 바로다음에는 add $_GLOBAL_OFFSET_TABLE_ 이 와야하므로 그부분만 좀 바꿔준다. [주의] add $0x123->$_GOT_ 가 되는데, 0x123은 PIE 에뮬레이션할때 사용됨. 따라서 이 작업은 모든작업이 끝난후에 하자. 
	post_getpcthunk_handling(resdic) 

	if options.align is True: 
		if '.text' in resdic.keys():
			resdic['.text'] = align_text(resdic['.text'])
		if '.rodata' in resdic.keys():
			resdic['.rodata'] = align_data(resdic['.rodata'])
		if '.data' in resdic.keys():
			resdic['.data'] = align_data(resdic['.data'])
		if '.bss' in resdic.keys():
			resdic['.bss'] = align_data(resdic['.bss'])
	

	if options.datainsert is True:
		for i in range(0, len(resdic['.rodata'])):
			if len(resdic['.rodata'].values()[i][0]) != 0: # 만약에 심볼이있다면 데이터처음부분에 INSRTED DATA 를넣자
				resdic['.rodata'].values()[i][1] = " .byte 0x49, 0x4e, 0x53, 0x45, 0x52, 0x54, 0x45, 0x44, 0x5f\n" + resdic['.rodata'].values()[i][1]
	

	if options.comment is True:
		gen_assemblyfile(LOC, resdic, options.filename, 1)
	else:
		gen_assemblyfile(LOC, resdic, options.filename, 0)


	# Select which script to generate!
	if mainaddr == -1: # library...maybe?
		gen_compilescript_for_sharedlibrary(LOC, options.filename)

	elif CHECKSEC_INFO.pie == True: # pie binary... without main (TODO: 이런일은 있을수가 없으므로 gen_assemblescript_for_piebinary 를 gen_compilescript_forPIE로 바꿀 것)
		gen_compilescript_for_piebinary(LOC, options.filename)

	else: # have main.. and not pie..!
		gen_compilescript(LOC, options.filename)
	

	onlyfilename = options.filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print "[*] input binary    : {}".format(options.filename)
	print "[+] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print "[+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print ""

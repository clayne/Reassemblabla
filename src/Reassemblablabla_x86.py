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






















	# ==테이블 셋팅==

	RELO_TABLES_RELDYN = readelf('.rel.dyn', options.filename) # '.rel.dyn' 와 '.rel.plt' 는 자매사이임. Full relro에서는 뭐를쓰고... 일반바이너리에서는 뭐를쓰고... 한다는데 사실 걍 둘다쳐주면 문제없지롱
	RELO_TABLES_RELPLT = readelf('.rel.plt', options.filename)
	REL_TABLE = RELO_TABLES_RELDYN + RELO_TABLES_RELPLT # 합쳤다 

	# TwoColumnize
	T_got2name = TwoColumnize('Relocation section',REL_TABLE, 'R_386_JUMP_SLOT', 'Type', 'Offset', 'Sym. Name') #  R_386_JUMP_SLOT : which is used for the normal PLT/GOT function call relocation mechanism. Offset(.plt.got의주소)을 키로가짐. 
	T_glob     = TwoColumnize('Relocation section',REL_TABLE, 'R_386_GLOB_DAT', 'Type', 'Offset', 'Sym. Name')   # 리턴테이블은 'Sym.Value'값 (실제 데이터나 함수가있는곳)을 키로가짐
	T_copy     = TwoColumnize('Relocation section',REL_TABLE, 'R_386_COPY', 'Type', 'Sym.Value', 'Sym. Name') 



	# stderr@GOT(%ebx) 붙여준다
	# 그리고 새로추가된룰 
	setsymbolnamefor_GLOB_DAT(T_glob)# 	# stderr 가 심볼이름이라면, stderr@GOT(%ebx) 로 심볼이름을 고쳐준다. 왜냐하면 나중에 이 심볼에접근할때 GOT에 저장되어있는 stderr객체의 주소에 접근할꺼거든. copy심볼은 got로 접근하는게아니라 곧장데이터섹션으로 접근하는거기때문에 원래의 심볼이름을 그대로 사용해도 됨. 








	
	T_plt2name = got2name_to_plt2name(T_got2name, CHECKSEC_INFO, resdic)# T_got2name 을 T_plt2name으로 바꾼다.
	T_ultimate = {}
	T_ultimate.update(T_plt2name) # 궁극의 다이나믹테이블을 만든다
	T_ultimate.update(T_glob) # data 가 key 인 경우가 있고, got 가 key 인 경우가 있는데, .got는 결국에 .data 섹션으로 write되니까, 
	T_ultimate.update(T_copy) # 두경우 모두 .data 섹션안의 다이나믹심볼을 MYSYM_다이나믹심볼로 바꾸면 해결되는문제임



	DYNSYM_TABLE = readelf('.dynsym', options.filename)
	T_symweak = TwoColumnize('Symbol table', DYNSYM_TABLE, 'WEAK', 'Bind', 'Value', 'Name')
	T_symglob = TwoColumnize('Symbol table', DYNSYM_TABLE, 'GLOBAL', 'Bind', 'Value', 'Name')


	# ==심볼리제이션=
	# 심볼리제이션 순서 1. Relocation section table 2. Weak symbol 3. Global symbol
	dynamic_symbol_labeling(resdic, T_ultimate) 
	dynamic_symbol_labeling(resdic, T_symweak) 
	dynamic_symbol_labeling(resdic, T_symglob) 

	pltsection_sanitize(resdic) # 이름없는 got로향하는 무의미한 plt들에 XXX 라는 더미이름을 하사해 주겠노라


























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
		resdic['.text'][startaddr][0] = "_start:"
	else: 
		resdic['.text'][mainaddr][0] = "main:"


	
	# 내일 출근해서 먼저 할것:
	# TODO: 모든 Writagble 섹션에 대해서 .dynsym 테이블에서 Dynamic symbol 목록을 긁어와다가 이름을 붙여주자. 
	# TODO: 이 안에는 WEAK심볼과 그냥심볼이 함께있는데, 둘다있다면 WEAK심볼을 택하자.
	# 예를들어 program_invocation_name과 __progname_full 이 공존하는데, 전자는 WEAK고 후자는 GLOBAL이다.
	# 그러므로 .dynsym 테이블을 파싱해서 받아온후에는 
	# 1. selectAttributeFromtReadelfTable (WEAK) 부터 받아서 위크심볼이름을 몽땅다 붙여준후에
	# 2. selectAttributeFromtReadelfTable (GLOBAL) 받아서 글로발심볼 붙여주고나서
	# 쩌~~~ 뒤에서 심볼리제이션 다하면 이러케 심볼붙여준값들을 not_global_symbolize_bss 이런거호출해서 흔적도없게함으로써 링커에게 할일을 넘기는거지...크크...
	# 그뒤에 .rel.plt .rel.dyn 의 R_386_GLOB_DATA 파싱해서 이름붙여줘야지
	'''
	symtab = get_dynsymtab(options.filename) 
	if '.bss' in resdic.keys() and '.bss' in symtab.keys() :
		global_symbolize_000section(resdic['.bss'], symtab['.bss'])
	
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys() and SectionName in symtab.keys():
			global_symbolize_000section(resdic[SectionName], symtab[SectionName])
	'''


	# 심볼라이즈 전에 brackets를 다 제거해야징
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			remove_brackets(resdic[SectionName]) 
	

	# get_pc_thunk 같은게 있을경우 이거 심볼라이즈
	pcthunk_reglist = PIE_symbolize_getpcthunk(resdic)


	# data, text 섹션들 심볼라이즈
	symbolize_textsection(resdic)
	symbolize_datasection(resdic)


	# get_pc_thunk 를 호출하는 라인의 EIP를 resdic[name][3]에다가 쓴다. 주의: get_pc_thunk를 호출하는지안하는지는 symbolize_textsection 을 거친후에야 알수있음
	PIE_return_getpcthunk_loc(resdic) 

	PIE_calculate_targetaddr(resdic)
	

	# TODO: 이 라인 활성화 ... 고쳐서 활성화..
	# PIE_calculate_remainedpointer_HEURISTICALLY(pcthunk_reglist, resdic)

	# 남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다 
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_remove_callweirdaddress(resdic[SectionName])

	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data(resdic[SectionName])
	





	# data sections 에 아직 남아있는 dynamic symbol 을 없애버린다. (심볼이 붙어있음 == 이름이 의미가 있음 == 링커가 알아서해주는 심볼임 == 없애도댐)
	print "resdic.keys() : {}".format(resdic.keys())
	not_global_symbolize_datasection(resdic)




	
	# weak_sym 의 이름을 불러주었을때 내게로 와 "w"위크심볼이 되었따리...
	# TODO: 이거 이제 없애줘도 됨. 왜냐면 .dynsym에 WEAK심볼의 이름이 있어서, 이걸보고 위크심볼호출해주면되기때문이믕 깨달았기때문임. 
	# please_call_my_name___by_weaksymbol(resdic['.text']) 




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
		# gen_assemblyfile(LOC, resdic, options.filename, symtab, 1)
		gen_assemblyfile(LOC, resdic, options.filename, T_symglob, 1)
	else:
		# gen_assemblyfile(LOC, resdic, options.filename, symtab, 0)
		gen_assemblyfile(LOC, resdic, options.filename, T_symglob, 0)


	# Select which script to generate!
	if mainaddr == -1: # library...maybe?
		gen_assemblescript_for_sharedlibrary(LOC, options.filename)

	elif CHECKSEC_INFO.pie == True: # pie binary... without main (TODO: 이런일은 있을수가 없으므로 gen_assemblescript_for_piebinary 를 gen_compilescript_forPIE로 바꿀 것)
		gen_assemblescript_for_piebinary(LOC, options.filename)

	else: # have main.. and not pie..!
		gen_compilescript(LOC, options.filename)
	
	# gen_assemblescript(LOC, options.filename) ==> 흔적기관.. 사용하지는 않을듯? 우선은 남겨둠. 

	onlyfilename = options.filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print "[*] input binary    : {}".format(options.filename)
	print "[+] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print "[+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print ""

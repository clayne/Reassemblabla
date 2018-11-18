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

	usage = "usage: %prog -f [FILE] <OPTIONS>"
	parser = OptionParser(usage=usage, version="%prog 1.0")
	parser.add_option("-f", "--filename", dest="filename", help="denote binary file")
	parser.add_option("-a", "--align", dest="align", help="align datas in data section", action="store_true")
	parser.add_option("-c", "--comment", dest="comment", help="add bytepattern info as a comment", action="store_true")
	parser.add_option("-d", "--datainsert", dest="datainsert", help="insert datas to data section", action="store_true")
	parser.add_option("-l", "--location", dest="location", help="location to save result files")
	parser.add_option("-s", "--shrinksize", dest="shrinksize", help="shrink output binary size by disignate local symbol", action="store_true")
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
		print "     --shrinksize : shrink output binary size by disignate local symbol" 
		sys.exit(0)

	if options.shrinksize is True: 
		print '[*] Shirinking size...'
		SYMPREFIX[0] = '.L' # 전역변수로써 접근해야하는데 로컬에서만 L이되서그런가?
	else:
		SYMPREFIX[0] = ''

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
	logging("get_relocation_tables")
	T_rel = get_relocation_tables(options.filename)





	# 컴파일타임에 자동으로추가됨. 그래서 .s에있어봣자 컴파일에러만 야기하는 쓸모없는것들제거 ['__gmon_start__', '_Jv_RegisterClasses', '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable']
	# eliminate_weird_GLOB_DAT(T_rel['R_386_GLOB_DAT']) # TODO: 이 함수 이제 필요없다아... 왜냐면 쓸모없는것들은 STT_NOTYPE 속성이기 때문이다




	# 이 직전에 .plt.got 부분이 더럽다면 jmpl *0xc(%ebx)이런시그로 점프하면 더럽거덩. 그러면 살짝 sanitizing을 하고가자. 
	logging("now PIE_LazySymbolize_GOTbasedpointer_pltgot")
	PIE_LazySymbolize_GOTbasedpointer_pltgot(CHECKSEC_INFO, resdic)

	# pie바이너리를 위한 테이블수정이 살짝 있겠습니다...
	if CHECKSEC_INFO.pie == True:
		concat_symbolname_to_TABLE(T_rel['STT_OBJECT'], '@GOT(REGISTER_WHO)')
		concat_symbolname_to_TABLE(T_rel['STT_FUNC'], '@PLT')


	# T_got2name 을 T_plt2name으로 바꾼다.
	T_plt2name = got2name_to_plt2name(T_rel['STT_FUNC'], CHECKSEC_INFO, resdic)






	# ==심볼이름 레이블링==. 레이블링 순서는 휘발성이강하고(weak) 국소적인 이름부터한다. 1. Relocation section table 2. Weak symbol 3. Global symbol
	logging("now labeling")
	dynamic_symbol_labeling(resdic, T_plt2name) 
	dynamic_symbol_labeling(resdic, T_rel['STT_OBJECT']) 
	########### dynamic_symbol_labeling(resdic, T_rel['STT_NOTYPE']) # STT_NOTYPE 은 절대심볼화안해줌 ㅋ 

	pltsection_sanitize(resdic) # 이름없는 got로향하는 무의미한 plt 들에 XXX 라는 더미이름을 하사해 주겠노라




	# main 을 labeling 하기 위한 20줄에 걸친 몸부림..
	__libc_start_main_addr = -1
	for addr in T_plt2name.keys():
		# print  T_plt2name[addr]
		if '__libc_start_main' in T_plt2name[addr]: # 함수이름이 __libc_start_main@PLT 인 경우가 있기때문에 in 을 써줌. 
			__libc_start_main_addr = addr
	if __libc_start_main_addr == -1:
		mainaddr = -1
	else:
		mainaddr = findmain(options.filename, resdic, __libc_start_main_addr, CHECKSEC_INFO)

	startaddr = findstart(options.filename)

	if mainaddr == -1: 
		resdic['.text'][startaddr][0] = SYMPREFIX[0] + "MYSYM_ENTRY:" # "_start:" 가 들어가면, 왠진모르겠지만 라이브러리의 call _start 에서 이상한 곳을 CALL 하게된다. 
	else: 
		resdic['.text'][mainaddr][0] = "main:"


	# 심볼라이즈 전에 brackets를 다 제거해야징
	logging("now remove_brackets")
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			remove_brackets(resdic[SectionName]) 
	

	# get_pc_thunk 같은게 있을경우 이거 심볼라이즈
	logging("now getpcthunk_labeling")
	pcthunk_reglist = getpcthunk_labeling(resdic)

	# ===일반 address 심볼라이즈===
	logging("now symbolize_textsection")
	symbolize_textsection(resdic)
	logging("now symbolize_datasection")
	symbolize_datasection(resdic)


	# ===calculated address 심볼라이즈===
	logging("now PIE_set_getpcthunk_loc")
	PIE_set_getpcthunk_loc(resdic) # get_pc_thunk 를 호출하는 라인의 EIP를 resdic[name][3]에다가 쓴다. 주의: get_pc_thunk를 호출하는지안하는지는 symbolize_textsection 을 거친후에야 알수있음
	PIE_calculated_addr_symbolize(resdic)
	

	# ===남은것들중 GOT베이스로다가 데이터에접근하는놈들 심볼라이즈===
	logging("now PIE_LazySymbolize_GOTbasedpointer")
	PIE_LazySymbolize_GOTbasedpointer(pcthunk_reglist, resdic,CHECKSEC_INFO)


	# ===남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다===
	logging("now lfunc_remove_callweirdaddress")
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_remove_callweirdaddress(resdic[SectionName])

	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data(resdic[SectionName])
	


	# ===마지막으로 call stderror@GOT(REGISTER_WHO)로 blank로 심볼리제이션된거 resdic[3]을 참조해서 레지스터자리채워주기===
	logging("now fill_blanked_symbolname_toward_GOTSECTION")
	fill_blanked_symbolname_toward_GOTSECTION(resdic)

	# === stderr 를 MYSYM_stderr로 바꿔버린다. (심볼이 붙어있음 == 이름이 의미가 있음 == 링커가 알아서해주는 심볼임 == 없애도댐)=== COMMENT:1116 data섹션에도 stderr가 박혀있고 .bss섹션에도 stderr가 박혀있는경우 재조립할때 동일한심볼이름 참조했다면서 에러남. 그래서 심볼이름에 섹션이름을 녹여넣도록했음. 
	logging("now not_global_symbolize_datasection")
	not_global_symbolize_datasection(resdic)

	# ===getpcthunk 바로다음에는 add $_GLOBAL_OFFSET_TABLE_ 이 와야하므로 그부분만 좀 바꿔준다. [주의] add $0x123->$_GOT_ 가 되는데, 0x123은 PIE 에뮬레이션할때 사용됨. 따라서 이 작업은 모든작업이 끝난후에 하자. 
	logging("now post_getpcthunk_handling")
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
	


	'''
	#여기서부터는 symbolize_lazy 루틴임.
	getpcthunk_to_returnoriginalADDR(resdic)

	add_stuffs(resdic, mainaddr) # 레이지리졸브에 필요한 백업함수를 추가하고, 그리구 main앞에 시그널핸들러를 등록하쟝

	# 모든 점프에대해서 세그폴발생할수도있으니깐 우선 백업(레지스터랑 플래그레지스터)부터하쟝
	jmp_to_PushalPushfJmp(resdic) 

	# 모든 라인에 심볼을 붙인다
	addLABEL_to_allLineofTextSection(resdic)

	# 레이지 리졸버 함수덩어리를 추가한다
	addLazyResolver2textSection(resdic)
	print "[*] Add  -Wl,--section-start=.text=0x09000000 to compile.sh!!"
	'''





	if options.comment is True:
		gen_assemblyfile(LOC, resdic, options.filename, 1)
	else:
		gen_assemblyfile(LOC, resdic, options.filename, 0)



	# 왜냐하면 x64머신에서는 x86바이너리에대해 compile script까지 만들어줄수가 없기때문임
	# (이상하게도 x86바이너리에대한 ldd가 안먹기때문인이유도있음) 
	logging("")
	logging("Finished generating disassembly file!!!")
	logging("Lets run Reassemblabla_x86_gencompilescript.py on x86 machine!")
	logging("")





	# Select which script to generate!
	if options.filename.endswith('.so') and mainaddr == -1: # library
		gen_compilescript_for_sharedlibrary(LOC, options.filename)

	elif CHECKSEC_INFO.pie == True : # pie binary...
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

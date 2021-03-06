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
	parser.add_option("", "--usesymboltable", dest="usesymboltable", help="generated comment depending on existing symbol table", action="store_true") # for BiOASAN
	
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
		SYMPREFIX[0] = '.L' # ?????????????????? ????????????????????? ??????????????? L???????????????????
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





	# ==????????? ??????== : .dynsym ??? ?????????????????? ??????. ???????????? .rel.dyn??? .rel.plt??? ?????????????????? ??????.
	logging("get_relocation_tables")
	T_rel = get_relocation_tables(options.filename)



	# ?????????????????? ?????????????????????. ????????? .s??????????????? ?????????????????? ???????????? ???????????????????????? ['__gmon_start__', '_Jv_RegisterClasses', '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable']
	#eliminate_weird_GLOB_DAT(T_rel['R_386_GLOB_DAT']) # COMMENT: ??? ?????? ?????? ???????????????... ????????? ????????????????????? STT_NOTYPE ???????????? ????????????




	# ??? ????????? .plt.got ????????? ???????????? jmpl *0xc(%ebx)??????????????? ???????????? ????????????. ????????? ?????? sanitizing??? ????????????. 
	if CHECKSEC_INFO.pie == True: # PIE ????????? ??????????????????X. ?????????. (????????????????????? ??????????????? jmp *0x12341234 ??? ?????? straightforward???)
		logging("now PIE_LazySymbolize_GOTbasedpointer_pltgot")
		PIE_LazySymbolize_GOTbasedpointer_pltgot(CHECKSEC_INFO, resdic)

	# pie??????????????? ?????? ?????????????????? ?????? ???????????????...
	if CHECKSEC_INFO.pie == True:
		logging("now concat_symbolname_to_TABLE")
		concat_symbolname_to_TABLE(T_rel['STT_OBJECT'], '@GOT(REGISTER_WHO)') # TODO: ?????? ?????? GOT relative access ??? ????????? ?????????? -->??????... GOT based access??? ????????? ??????????????? ????????? 
		# concat_symbolname_to_TABLE(T_rel['STT_FUNC'], '@PLT') # COMMENT : ????????? ?????? ????????? ???????????? ????????? ??????. ????????? ?????? @PLT ?????????. 
		

	# T_got2name ??? T_plt2name?????? ?????????.
	logging("now got2name_to_plt2name...")
	T_plt2name = got2name_to_plt2name(T_rel['STT_FUNC'], CHECKSEC_INFO, resdic)



	# ==???????????? ????????????==. ???????????? ????????? ?????????????????????(weak) ???????????? ??????????????????. 1. Relocation section table 2. Weak symbol 3. Global symbol
	logging("now dynamic_symbol_labeling...")
	dynamic_symbol_labeling(resdic, T_plt2name) 
	dynamic_symbol_labeling(resdic, T_rel['STT_OBJECT']) 
	########### dynamic_symbol_labeling(resdic, T_rel['STT_NOTYPE']) # STT_NOTYPE ??? ???????????????????????? ??? 

	pltsection_sanitize(resdic) # ???????????? got???????????? ???????????? plt ?????? XXX ?????? ??????????????? ????????? ????????????



	# main ??? labeling ?????? ?????? 20?????? ?????? ?????????..
	__libc_start_main_addr = -1
	for addr in T_plt2name.keys():
		# print  T_plt2name[addr]
		if '__libc_start_main' in T_plt2name[addr]: # ??????????????? __libc_start_main@PLT ??? ????????? ??????????????? in ??? ??????. 
			__libc_start_main_addr = addr
	if __libc_start_main_addr == -1:
		mainaddr = -1
	else:
		mainaddr = findmain(options.filename, resdic, __libc_start_main_addr, CHECKSEC_INFO)

	startaddr = findstart(options.filename)


	if mainaddr == -1: 
		resdic['.text'][startaddr][0] = SYMPREFIX[0] + "MYSYM_ENTRY:" # "_start:" ??? ????????????, ????????????????????? ?????????????????? call _start ?????? ????????? ?????? CALL ????????????. 
	else: 
		resdic['.text'][mainaddr][0] = "main:"


	# get_pc_thunk ????????? ???????????? ?????? ???????????????
	logging("now getpcthunk_labeling")
	pcthunk_reglist = getpcthunk_labeling(resdic)

	# ===?????? address ???????????????===
	logging("now symbolize_textsection")
	symbolize_textsection(resdic)
	logging("now symbolize_datasection")
	symbolize_datasection(resdic)


	# ===calculated address ???????????????===
	logging("now PIE_set_getpcthunk_loc")
	PIE_set_getpcthunk_loc(resdic) # get_pc_thunk ??? ???????????? ????????? EIP??? resdic[name][3]????????? ??????. ??????: get_pc_thunk??? ?????????????????????????????? symbolize_textsection ??? ??????????????? ????????????
	logging("now PIE_calculated_addr_symbolize")
	PIE_calculated_addr_symbolize(resdic)
	

	# ===??????????????? GOT?????????????????? ?????????????????????????????? ???????????????===
	logging("now PIE_LazySymbolize_GOTbasedpointer")
	PIE_LazySymbolize_GOTbasedpointer(pcthunk_reglist, resdic,CHECKSEC_INFO) 


	# ===???????????? (symbolization ??? ?????? ??????) ??? ??????????????? ????????????===
	logging("now lfunc_remove_callweirdaddress")
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_callweirdaddress_2_callXXX(resdic[SectionName])

	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_callweirdaddress_2_data(resdic[SectionName])
	




	# ===??????????????? call stderror@GOT(REGISTER_WHO)??? blank??? ???????????????????????? resdic[3]??? ???????????? ??????????????????????????????===
	logging("now fill_blanked_symbolname_toward_GOTSECTION")
	fill_blanked_symbolname_toward_GOTSECTION(resdic)
                                                                                                                                                                     
	# === stderr ??? MYSYM_stderr??? ???????????????. (????????? ???????????? == ????????? ????????? ?????? == ????????? ?????????????????? ????????? == ????????????)=== COMMENT:1116 data???????????? stderr??? ???????????? .bss???????????? stderr??? ?????????????????? ??????????????? ????????????????????? ?????????????????? ?????????. ????????? ??????????????? ??????????????? ?????????????????????. 
	logging("now not_global_symbolize_ExternalLinkedSymbol")
	not_global_symbolize_ExternalLinkedSymbol(resdic)



	logging("now add_routine_to_get_GLOBAL_OFFSET_TABLE_at_init_array")
	add_routine_to_get_GLOBAL_OFFSET_TABLE_at_init_array(resdic)



	# ===getpcthunk ?????????????????? add $_GLOBAL_OFFSET_TABLE_ ??? ??????????????? ???????????? ??? ????????????. [??????] add $0x123->$_GOT_ ??? ?????????, 0x123??? PIE ????????????????????? ?????????. ????????? ??? ????????? ??????????????? ???????????? ??????. 
	'''
	logging("now post_getpcthunk_handling") 
	post_getpcthunk_handling(resdic) # ?????? ??????. ???????????? ebx ??? ?????????????????????????????? GOT??? ???????????????, ???????????? ?????????????????? ????????? ????????? ???????????????????????? ????????? ?????????
	'''



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
			if len(resdic['.rodata'].values()[i][0]) != 0: # ????????? ?????????????????? ???????????????????????? INSRTED DATA ?????????
				resdic['.rodata'].values()[i][1] = " .byte 0x49, 0x4e, 0x53, 0x45, 0x52, 0x54, 0x45, 0x44, 0x5f\n" + resdic['.rodata'].values()[i][1]
	


	'''
	#?????????????????? symbolize_lazy ?????????.
	getpcthunk_to_returnoriginalADDR(resdic)

	add_stuffs(resdic, mainaddr) # ????????????????????? ????????? ??????????????? ????????????, ????????? main?????? ????????????????????? ????????????

	# ?????? ?????????????????? ???????????????????????????????????? ?????? ??????(??????????????? ?????????????????????)????????????
	jmp_to_PushalPushfJmp(resdic) 

	# ?????? ????????? ????????? ?????????
	addLABEL_to_allLineofTextSection(resdic)

	# ????????? ????????? ?????????????????? ????????????
	addLazyResolver2textSection(resdic)
	print "[*] Add  -Wl,--section-start=.text=0x09000000 to compile.sh!!"
	'''

	SYMTAB = []
	if options.usesymboltable is True:
		SYMTAB = get_SYM_LIST(options.filename)
	gen_assemblyfile(LOC, resdic, options.filename, CHECKSEC_INFO, options.comment, SYMTAB)


	# ???????????? x64??????????????? x86????????????????????? compile script?????? ?????????????????? ???????????????
	# (??????????????? x86????????????????????? ldd??? ?????????????????????????????????) 
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

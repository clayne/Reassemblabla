#!/usr/bin/python
#-*- coding: utf-8 -*-
from optparse import OptionParser
from pwn import *

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
	parser.add_option("", "--testing", dest="testingcrashhandler", help="now testing about crashhandler relative features... hope it works without any issues.", action="store_true")
	
	parser.set_defaults(verbose=True)
	(options, args) = parser.parse_args()
	
	if options.filename is None:
		print "Usage : python Reassemblabla.py -f [BINARY] <OPTION>"
		print "     --align   		 : lign datas in data section" 
		print "     --insert  		 : insert datas to data section" 
		print "     --comment 	 	 : add bytepattern info as a comment" 
		print "     --location 		 : denote location(directory) to save the result files" 
		print "     --shrinksize 	 : shrink output binary size by disignate local symbol" 
		print "     --usesymboltable : generated comment depending on existing symbol table"
		sys.exit(0)

	if options.shrinksize is True: 
		logging("Shirinking size...")
		SYMPREFIX[0] = '.L' #TODO: 생각해보니까 심볼 라벨링할때 이거 적용안했던것들이 있었다. 나중에 적용해줄 것.
	else:
		SYMPREFIX[0] = ''

	if options.location is None:
		LOC = '.'
		logging("Result files will be saved at default location! ---> {}".format(LOC))

	else:
		LOC = options.location
		logging("Result files will be saved at.. ---> {}".format(LOC))
		if not os.path.exists(LOC): 
			print " [!] Designated location does not exist!"
			sys.exit(0)


	SHTABLE = get_shtable(options.filename)

	# initialize resdic
	resdic = binarycode2dic(options.filename, SHTABLE)
	resdic_data = binarydata2dic(options.filename)
	resdic.update(resdic_data)



	CHECKSEC_INFO = pwnlib.elf.elf.ELF(options.filename, False)



	# 심볼화에 사용할 다이나믹심볼들을 구해온다. (.dynsym 은 처리안해줘도 된다. 왜냐하면 .rel.dyn과 .rel.plt에 포함되어있기 때문)
	logging("get_relocation_tables")
	T_rel = get_relocation_tables(options.filename)


	# PIE라면 외부라이브러리 resolve를 해주기 위해 휴리스틱 필요. (.plt.got 부분이 jmpl *0xc(%ebx)이렇게 생겨서 원샷에 resolve 못한다)
	if CHECKSEC_INFO.pie == True:  
		logging("now PIE_LazySymbolize_GOTbasedpointer_pltgot")
		PIE_LazySymbolize_GOTbasedpointer_pltgot(CHECKSEC_INFO, resdic)

	# pie바이너리를 위한 테이블수정...
	if CHECKSEC_INFO.pie == True:
		logging("now concat_symbolname_to_TABLE")
		concat_symbolname_to_TABLE(T_rel['STT_OBJECT'], '@GOT(REGISTER_WHO)') # 근데 굳이 GOT relative access 를 안해도 되잖아? -->아냐... GOT based access가 아니면 컴파일러가 불평함
		# concat_symbolname_to_TABLE(T_rel['STT_FUNC'], '@PLT') # COMMENT : 이렇게 하면 링킹을 못해오는 경우가 발생. 그래서 그냥 @PLT 빼줬다. 
		
	# T_got2name 을 T_plt2name으로 바꾼다.
	logging("now got2name_to_plt2name...")
	T_plt2name = got2name_to_plt2name(T_rel['STT_FUNC'], CHECKSEC_INFO, resdic)


	# 심볼이름 레이블링. 레이블링 순서는 휘발성이강하고(weak) 국소적인 이름부터한다. 1. Relocation section table 2. Weak symbol 3. Global symbol
	logging("now dynamic_symbol_labeling...")
	dynamic_symbol_labeling(resdic, T_plt2name) 
	dynamic_symbol_labeling(resdic, T_rel['STT_OBJECT']) 
	# dynamic_symbol_labeling(resdic, T_rel['STT_NOTYPE']) # STT_NOTYPE 은 심볼화해주면 컴파일이 안된다. 주의.



	# main 을 찾는다.
	__libc_start_main_addr = -1
	for addr in T_plt2name.keys():
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


	# get_pc_thunk 같은게 있을경우 이거부터 심볼라이즈
	logging("now getpcthunk_labeling")
	pcthunk_reglist = getpcthunk_labeling(resdic)

	# 일반 심볼 심볼라이즈
	logging("now symbolize_textsection")
	symbolize_textsection(resdic)
	logging("now symbolize_datasection")
	symbolize_datasection(resdic)

	# 에뮬레이션을 이용한 심볼라이즈
	logging("now PIE_set_getpcthunk_loc")
	PIE_set_getpcthunk_loc(resdic) # 주의: get_pc_thunk를 호출하는지안하는지는 symbolize_textsection 을 거친후에야 알수있다. 함수 호출순서가 항상 뒤에오도록 신경써줄 것
	logging("now PIE_calculated_addr_symbolize")
	PIE_calculated_addr_symbolize(resdic, options.testingcrashhandler)
	
	# 휴리스틱을 이용한 심볼라이즈 (GOT 베이스로 데이터에 접근하는 경우 휴리스틱 이용)
	logging("now PIE_LazySymbolize_GOTbasedpointer")
	PIE_LazySymbolize_GOTbasedpointer(pcthunk_reglist, resdic,CHECKSEC_INFO) 

	# symbolization 이 안된 것들은 쓰레기통으로 보낸다. TODO: crash based design에서는 이렇게 해줄 필요 없음. 패치필요.
	logging("now lfunc_change_callweirdaddress_2_callXXX")
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_callweirdaddress_2_callXXX(resdic[SectionName])
	logging("now lfunc_change_callweirdaddress_2_data")
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_callweirdaddress_2_data(resdic[SectionName])
	

	# 링킹된 함수에서 비어있는 레지스터자리 채워주기. ex) call stderror@GOT(REGISTER_WHO)로 blank로 심볼리제이션된거 resdic[3]을 참조해서 레지스터자리 채워준다.
	logging("now fill_blanked_symbolname_toward_GOTSECTION")
	fill_blanked_symbolname_toward_GOTSECTION(resdic)
                                                                                                                                                                     
	# 링킹된 글로벌데이터 이름을 망가뜨린다. ex) stderr 를 MYSYM_stderr로 바꿔버린다. (심볼이 붙어있음 == 이름이 의미가 있음 == 링커가 알아서해주는 심볼임 == 없애도 된다)
	logging("now not_global_symbolize_ExternalLinkedSymbol")
	not_global_symbolize_ExternalLinkedSymbol(resdic)

	# 재조립 바이너리에서의 GOT를 얻어오는(필요할지도 모르므로) 루틴을 생성자배열에 추가.
	logging("now add_routine_to_get_GLOBAL_OFFSET_TABLE_at_init_array")
	addRoutineToGetGLOBALOFFSETTABLE_in_init_array(resdic)


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
	


	# 크래시핸들러 관련 루틴. 구현중
	if options.testingcrashhandler is True:
		# 모든메모리참조 전에 레지스터 컨텍스트 백업
		add_someprefix_before_all_memory_reference(resdic)
		
		# 마찬자지로 립씨함수같은거 앞에도 똑같이 백업한다
		add_someprefix_before_all_external_functioncall(resdic)

		# 모든라인에 심볼화
		symbolize_alllines(resdic) 
		# 시그널핸들러를 마련한다.
		setupsignalhandler(resdic)
		# 시그널핸들러를 설치한다.
		addRoutineToInstallSignalHandler_in_init_array(resdic) # COMMENT:setupsignalhandler 후에 실행하도록 신경써줄 것.
		setup_some_useful_stuffs_for_crashhandler(resdic)
		
		# getpcthunk 가 원본주소를 리턴하도록 한다. (크래시-친화적-디자인)
		getpcthunk_to_returnoriginalADDR(resdic)
	



	SYMTAB = []
	if options.usesymboltable is True:
		SYMTAB = get_SYM_LIST(options.filename)

	gen_assemblyfile(LOC, resdic, options.filename, CHECKSEC_INFO, options.comment, SYMTAB)


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
		gen_compilescript(LOC, options.filename, options.testingcrashhandler)
	

	onlyfilename = options.filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print " [*] input binary    : {}".format(options.filename)
	print " [+] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print " [+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print ""

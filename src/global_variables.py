#!/usr/bin/python
#-*- coding: utf-8 -*-

CodeSections_WRITE = ['.text','.init','.fini', '.ctors', '.dtors', '.plt.got','.plt']
DataSections_WRITE = ['.data','.rodata','.bss','.init_array','.fini_array','.got', '.jcr', '.data1', '.rodata1', '.tbss', '.tdata','.got.plt'] # <.jcr> added for handling pie binary.
AllSections_WRITE = CodeSections_WRITE + DataSections_WRITE

MyNamedSymbol = ['main', '__x86.get_pc_thunk']

CodeSections_IN_resdic = CodeSections_WRITE # TODO: 이거 없애준다음에 코드전반적으로 이거호출하는것도 수정하기. 
DataSections_IN_resdic = DataSections_WRITE 

AllSection_IN_resdic = CodeSections_IN_resdic + DataSections_IN_resdic

# URGENT: 아래 코드는 plt,got 잘 따져가면서 다시설계해라. 왜냐하면 libstdbuf.so 예젅디스어셈블버전하고 맞추려고 이렇게 설정했을뿐이니까.
'''
TreatThisSection2TEXT = ['.plt.got','.plt','.init','.fini', '.ctors', '.dtors']
TreatThisSection2DATA = ['.got', '.got.plt', '.jcr', '.data1', '.rodata1', '.tbss', '.tdata']
'''
TreatThisSection2TEXT = ['.init','.fini', '.ctors', '.dtors', '.plt.got', '.plt']
TreatThisSection2DATA = ['.jcr', '.data1', '.rodata1', '.tbss', '.tdata', '.got', '.got.plt']

DoNotWriteThisSection = [] # 걍 다 써줘봐봐우선. 

# for gen_assemblescript... Why crtn
# crts = "/usr/lib/i386-linux-gnu/crtn.o" # original...
# crts = "/usr/lib/i386-linux-gnu/crtn.o /usr/lib/i386-linux-gnu/crti.o "   # -> after execute binary, segfault happens
# crts = "/usr/lib/i386-linux-gnu/crtn.o /usr/lib/i386-linux-gnu/crti.o /usr/local/lib/gcc/i686-pc-linux-gnu/5.5.0/crtbegin.o " -> linking error happens
crts = "/usr/lib/i386-linux-gnu/crtn.o "

SYMPREFIX = ['']

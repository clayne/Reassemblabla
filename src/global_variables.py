CodeSections_WRITE = ['.text','.init','.fini', '.ctors', '.dtors', '.plt.got']
DataSections_WRITE = ['.data','.rodata','.bss','.init_array','.fini_array','.got', '.jcr', '.data1', '.rodata1', '.tbss', '.tdata'] # <.jcr> added for handling pie binary.
AllSections_WRITE = CodeSections_WRITE + DataSections_WRITE

CodeSections_IN_resdic = CodeSections_WRITE + ['.plt'] 
DataSections_IN_resdic = DataSections_WRITE + ['.got.plt'] 
AllSection_IN_resdic = CodeSections_IN_resdic + DataSections_IN_resdic

# for gen_assemblescript... Why crtn
# crts = "/usr/lib/i386-linux-gnu/crtn.o" # original...
# crts = "/usr/lib/i386-linux-gnu/crtn.o /usr/lib/i386-linux-gnu/crti.o "   # -> after execute binary, segfault happens
# crts = "/usr/lib/i386-linux-gnu/crtn.o /usr/lib/i386-linux-gnu/crti.o /usr/local/lib/gcc/i686-pc-linux-gnu/5.5.0/crtbegin.o " -> linking error happens
crts = "/usr/lib/i386-linux-gnu/crtn.o "
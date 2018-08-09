as -o ex_reassemblable.o ex_reassemblable.s
ld -o ex_reassemblable -dynamic-linker /lib/ld-linux.so.2  /usr/lib/i386-linux-gnu/crti.o -lc ex_reassemblable.o /usr/lib/i386-linux-gnu/crtn.o
as -o libjiwon.so.1.25_reassemblable.o libjiwon.so.1.25_reassemblable.s
ld -shared -soname libjiwon.so.1 -o libjiwon.so.1.25_reassemblable -dynamic-linker /lib/ld-linux.so.2 -lc  /lib/i386-linux-gnu/libc.so.6 libjiwon.so.1.25_reassemblable.o /usr/lib/i386-linux-gnu/crtn.o

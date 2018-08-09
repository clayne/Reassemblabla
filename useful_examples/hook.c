// gcc -o hook.so hook.c -fPIC -shared -ldl
// LD_PRELOAD=./hook.so /bin/ls
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>

void myinit(){
}
void myfini(){
}

int __libc_start_main(int (*main)(int,char**,char**), int argc, char** ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (* stack_end)){

	int (*__libc_start_main_orig)(int (*)(int,char**,char**), int, char**, void (*)(), void(*)(), void(*)(), void(*)) = NULL;
        __libc_start_main_orig = dlsym(RTLD_NEXT, "__libc_start_main");
	//printf("hahaha!\n");
	return __libc_start_main_orig(main, argc, ubp_av, myinit, myfini, rtld_fini, stack_end);

}

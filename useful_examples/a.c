// gcc -o a a.c -fpic -pie
#include <stdio.h>

void main(){
        malloc(1);
        malloc(2);
        printf("malloc\n");
        free(0);
        free(0);
        printf("freed\n");
        printf("hello world\n");
}


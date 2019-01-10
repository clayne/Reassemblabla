// COMPILE : gcc -o test test.c -L./ -ljiwon
// EXECUTE : LD_PRELOAD=./libjiwon.so ./test
#include <stdio.h>
#include <string.h>

int main()
{
    int sum = ysum(4,1);
    int diff = ydiff(4,1);
    printf("sum : %d, diff : %d\n",sum,diff);
}

// gcc -c libjiwon.c
// gcc -shared -Wl,-soname,libjiwon.so.1 -o libjiwon.so.1.25 libjiwon.o


int ysum(int a, int b); 
int ydiff(int a, int b);

int ysum(int a, int b)
{
    return a + b; 
}
int ydiff(int a, int b)
{
    return a - b;
}

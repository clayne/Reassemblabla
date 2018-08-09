#include <stdio.h>
#include <crypt.h>
 
int main(int argc, char* argv[])
{
        printf("%s\n", crypt(argv[1], argv[2]));
        return 0;
}

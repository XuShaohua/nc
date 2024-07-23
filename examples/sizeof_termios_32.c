
#include <stdio.h>
#include <termios.h>

int main(void)
{
    printf("NCCS = %d\n", NCCS);
    printf("sizeof(termios) = %lu\n", sizeof(struct termios));
    return 0;
}

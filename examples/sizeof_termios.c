
#include <stdio.h>
#include <asm/termios.h>

int main(void)
{
    printf("NCCS = %d\n", NCCS);
    printf("sizeof(termios) = %lu\n", sizeof(struct termios));
    printf("sizeof(termios2) = %lu\n", sizeof(struct termios2));
    return 0;
}

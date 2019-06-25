
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>

int main(void) {
  printf("TCGETS2: %d\n", TCGETS2);
  printf("TIOCSPTLCK: %ld\n", TIOCSPTLCK);
  printf("TIOCGPTN: %ld\n", TIOCGPTN);
}

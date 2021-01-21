
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static void sig_handler(int sig) {
  const char* msg = "Cauth Signal.\n";
  write(STDOUT_FILENO, msg, strlen(msg));
}

int main(void) {
  struct sigaction sa;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = sig_handler;
  if (sigaction(SIGALRM, &sa, NULL) == -1) {
    perror("sigaction()");
    return 1;
  }
  alarm(2);
  pause();

  return 0;
}

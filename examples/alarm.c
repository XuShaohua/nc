
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void handle_alarm_signal(int sig) {
  (void) sig;
}

int main() {
  signal(SIGALRM, handle_alarm_signal);

  int r = alarm(1);
  sleep(2);
  printf("r: %d\n", r);
  return 0;
}

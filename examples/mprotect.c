#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#define handle_error(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

static char *buffer;

static void handler(int sig, siginfo_t *si, void *unused) {
  /* Note: calling printf() from a signal handler is not safe
     (and should not be done in production programs), since
     printf() is not async-signal-safe; see signal-safety(7).
     Nevertheless, we use printf() here as a simple way of
     showing that the handler was called. */

  printf("Got SIGSEGV at address: %p\n", si->si_addr);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int pagesize;
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  //sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1)
    handle_error("sigaction");

  pagesize = sysconf(_SC_PAGE_SIZE);
  if (pagesize == -1)
    handle_error("sysconf");

  /* Allocate a buffer aligned on a page boundary;
     initial protection is PROT_READ | PROT_WRITE */

  buffer = memalign(pagesize, 4 * pagesize);
  if (buffer == NULL)
    handle_error("memalign");

  printf("Start of region:        %p\n", buffer);

  if (mprotect(buffer + pagesize * 2, pagesize, PROT_READ) == -1)
    handle_error("mprotect");

  for (char *p = buffer;;)
    *(p++) = 'a';

  printf("Loop completed\n"); /* Should never happen */
  exit(EXIT_SUCCESS);
}

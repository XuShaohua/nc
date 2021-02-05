
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

int main() {
    int real_prot = PROT_READ|PROT_WRITE;
    int pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
    void * ptr = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    int ret = pkey_mprotect(ptr, PAGE_SIZE, real_prot, pkey);
    return 0;
}

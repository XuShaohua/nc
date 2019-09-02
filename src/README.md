
## How to get syscall asm instructions?
musl project contains syscall asm instructioins of main architectures,
We can use this command to generate readable asm code:

```bash
$ gcc -E ${arch}/syscall_arch.h
```

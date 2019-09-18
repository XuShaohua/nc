
## How to get syscall asm instructions?
musl project contains syscall asm instructioins of main architectures,
We can use this command to generate readable asm code:

```bash
$ gcc -E ${arch}/syscall_arch.h
```

## How to install debian sysroot?
First install deps:
```bash
$ sudo apt install qemu-user-static debootstrap
```

Then create sysroot of specific architecture:
```bash
$ sudo debootstrap --arch aarch64 buster aarch64-root http://ftp.cn.debian.org/debian
```
Here:
* `--arch aarch64`, use `aarch64`
* `buster`, use latest debian stable image
* `aarch64-root`, rootfs folder name
* `http://ftp.cn.debian.org/debian`, debian mirror url. Most of unofficial debian
mirrors do not support non-x86 architectures

## TODO
- [x] support freebsd
- [ ] support windows
- [x] sighandler types
- [x] implement more syscalls
- [x] test arm
- [x] test mips
- [x] test mipsel
- [x] test ppc64
- [x] test ppc64le
- [ ] test s390x
- [x] add linux uapi types
- [x] remove little endians
- [ ] linux socket example
- [ ] big endian/litten endian bitwise integers
- [x] cstring issue
- [x] support stable version
- [x] derive Clone, Default traits
- [x] fix stat_t type error
- [ ] simplify syscalls
- [ ] fix siginfo_t
- [ ] u64 to usize error (32bits arch)
- [ ] `struct *timespec_t timeout` is NULL or not
- [ ] fix alignment issue in perf_events.rs
- [ ] arch specific types

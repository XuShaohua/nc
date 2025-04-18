// Code generated by mksysnum_linux.py; DO NOT EDIT.

use crate::syscalls::Sysno;

pub const SYS_EXIT: Sysno = 1;
pub const SYS_FORK: Sysno = 2;
pub const SYS_READ: Sysno = 3;
pub const SYS_WRITE: Sysno = 4;
pub const SYS_OPEN: Sysno = 5;
pub const SYS_CLOSE: Sysno = 6;
pub const SYS_RESTART_SYSCALL: Sysno = 7;
pub const SYS_CREAT: Sysno = 8;
pub const SYS_LINK: Sysno = 9;
pub const SYS_UNLINK: Sysno = 10;
pub const SYS_EXECVE: Sysno = 11;
pub const SYS_CHDIR: Sysno = 12;
pub const SYS_MKNOD: Sysno = 14;
pub const SYS_CHMOD: Sysno = 15;
pub const SYS_LSEEK: Sysno = 19;
pub const SYS_GETPID: Sysno = 20;
pub const SYS_MOUNT: Sysno = 21;
pub const SYS_UMOUNT: Sysno = 22;
pub const SYS_PTRACE: Sysno = 26;
pub const SYS_ALARM: Sysno = 27;
pub const SYS_PAUSE: Sysno = 29;
pub const SYS_UTIME: Sysno = 30;
pub const SYS_ACCESS: Sysno = 33;
pub const SYS_NICE: Sysno = 34;
pub const SYS_SYNC: Sysno = 36;
pub const SYS_KILL: Sysno = 37;
pub const SYS_RENAME: Sysno = 38;
pub const SYS_MKDIR: Sysno = 39;
pub const SYS_RMDIR: Sysno = 40;
pub const SYS_DUP: Sysno = 41;
pub const SYS_PIPE: Sysno = 42;
pub const SYS_TIMES: Sysno = 43;
pub const SYS_BRK: Sysno = 45;
pub const SYS_SIGNAL: Sysno = 48;
pub const SYS_ACCT: Sysno = 51;
pub const SYS_UMOUNT2: Sysno = 52;
pub const SYS_IOCTL: Sysno = 54;
pub const SYS_FCNTL: Sysno = 55;
pub const SYS_SETPGID: Sysno = 57;
pub const SYS_UMASK: Sysno = 60;
pub const SYS_CHROOT: Sysno = 61;
pub const SYS_USTAT: Sysno = 62;
pub const SYS_DUP2: Sysno = 63;
pub const SYS_GETPPID: Sysno = 64;
pub const SYS_GETPGRP: Sysno = 65;
pub const SYS_SETSID: Sysno = 66;
pub const SYS_SIGACTION: Sysno = 67;
pub const SYS_SIGSUSPEND: Sysno = 72;
pub const SYS_SIGPENDING: Sysno = 73;
pub const SYS_SETHOSTNAME: Sysno = 74;
pub const SYS_SETRLIMIT: Sysno = 75;
pub const SYS_GETRUSAGE: Sysno = 77;
pub const SYS_GETTIMEOFDAY: Sysno = 78;
pub const SYS_SETTIMEOFDAY: Sysno = 79;
pub const SYS_SYMLINK: Sysno = 83;
pub const SYS_READLINK: Sysno = 85;
pub const SYS_USELIB: Sysno = 86;
pub const SYS_SWAPON: Sysno = 87;
pub const SYS_REBOOT: Sysno = 88;
pub const SYS_READDIR: Sysno = 89;
pub const SYS_MMAP: Sysno = 90;
pub const SYS_MUNMAP: Sysno = 91;
pub const SYS_TRUNCATE: Sysno = 92;
pub const SYS_FTRUNCATE: Sysno = 93;
pub const SYS_FCHMOD: Sysno = 94;
pub const SYS_GETPRIORITY: Sysno = 96;
pub const SYS_SETPRIORITY: Sysno = 97;
pub const SYS_STATFS: Sysno = 99;
pub const SYS_FSTATFS: Sysno = 100;
pub const SYS_SOCKETCALL: Sysno = 102;
pub const SYS_SYSLOG: Sysno = 103;
pub const SYS_SETITIMER: Sysno = 104;
pub const SYS_GETITIMER: Sysno = 105;
pub const SYS_STAT: Sysno = 106;
pub const SYS_LSTAT: Sysno = 107;
pub const SYS_FSTAT: Sysno = 108;
pub const SYS_LOOKUP_DCOOKIE: Sysno = 110;
pub const SYS_VHANGUP: Sysno = 111;
pub const SYS_IDLE: Sysno = 112;
pub const SYS_WAIT4: Sysno = 114;
pub const SYS_SWAPOFF: Sysno = 115;
pub const SYS_SYSINFO: Sysno = 116;
pub const SYS_IPC: Sysno = 117;
pub const SYS_FSYNC: Sysno = 118;
pub const SYS_SIGRETURN: Sysno = 119;
pub const SYS_CLONE: Sysno = 120;
pub const SYS_SETDOMAINNAME: Sysno = 121;
pub const SYS_UNAME: Sysno = 122;
pub const SYS_ADJTIMEX: Sysno = 124;
pub const SYS_MPROTECT: Sysno = 125;
pub const SYS_SIGPROCMASK: Sysno = 126;
pub const SYS_CREATE_MODULE: Sysno = 127;
pub const SYS_INIT_MODULE: Sysno = 128;
pub const SYS_DELETE_MODULE: Sysno = 129;
pub const SYS_GET_KERNEL_SYMS: Sysno = 130;
pub const SYS_QUOTACTL: Sysno = 131;
pub const SYS_GETPGID: Sysno = 132;
pub const SYS_FCHDIR: Sysno = 133;
pub const SYS_BDFLUSH: Sysno = 134;
pub const SYS_SYSFS: Sysno = 135;
pub const SYS_PERSONALITY: Sysno = 136;
pub const SYS_AFS_SYSCALL: Sysno = 137;
pub const SYS_GETDENTS: Sysno = 141;
pub const SYS_SELECT: Sysno = 142;
pub const SYS_FLOCK: Sysno = 143;
pub const SYS_MSYNC: Sysno = 144;
pub const SYS_READV: Sysno = 145;
pub const SYS_WRITEV: Sysno = 146;
pub const SYS_GETSID: Sysno = 147;
pub const SYS_FDATASYNC: Sysno = 148;
pub const SYS__SYSCTL: Sysno = 149;
pub const SYS_MLOCK: Sysno = 150;
pub const SYS_MUNLOCK: Sysno = 151;
pub const SYS_MLOCKALL: Sysno = 152;
pub const SYS_MUNLOCKALL: Sysno = 153;
pub const SYS_SCHED_SETPARAM: Sysno = 154;
pub const SYS_SCHED_GETPARAM: Sysno = 155;
pub const SYS_SCHED_SETSCHEDULER: Sysno = 156;
pub const SYS_SCHED_GETSCHEDULER: Sysno = 157;
pub const SYS_SCHED_YIELD: Sysno = 158;
pub const SYS_SCHED_GET_PRIORITY_MAX: Sysno = 159;
pub const SYS_SCHED_GET_PRIORITY_MIN: Sysno = 160;
pub const SYS_SCHED_RR_GET_INTERVAL: Sysno = 161;
pub const SYS_NANOSLEEP: Sysno = 162;
pub const SYS_MREMAP: Sysno = 163;
pub const SYS_QUERY_MODULE: Sysno = 167;
pub const SYS_POLL: Sysno = 168;
pub const SYS_NFSSERVCTL: Sysno = 169;
pub const SYS_PRCTL: Sysno = 172;
pub const SYS_RT_SIGRETURN: Sysno = 173;
pub const SYS_RT_SIGACTION: Sysno = 174;
pub const SYS_RT_SIGPROCMASK: Sysno = 175;
pub const SYS_RT_SIGPENDING: Sysno = 176;
pub const SYS_RT_SIGTIMEDWAIT: Sysno = 177;
pub const SYS_RT_SIGQUEUEINFO: Sysno = 178;
pub const SYS_RT_SIGSUSPEND: Sysno = 179;
pub const SYS_PREAD64: Sysno = 180;
pub const SYS_PWRITE64: Sysno = 181;
pub const SYS_GETCWD: Sysno = 183;
pub const SYS_CAPGET: Sysno = 184;
pub const SYS_CAPSET: Sysno = 185;
pub const SYS_SIGALTSTACK: Sysno = 186;
pub const SYS_SENDFILE: Sysno = 187;
pub const SYS_GETPMSG: Sysno = 188;
pub const SYS_PUTPMSG: Sysno = 189;
pub const SYS_VFORK: Sysno = 190;
pub const SYS_GETRLIMIT: Sysno = 191;
pub const SYS_LCHOWN: Sysno = 198;
pub const SYS_GETUID: Sysno = 199;
pub const SYS_GETGID: Sysno = 200;
pub const SYS_GETEUID: Sysno = 201;
pub const SYS_GETEGID: Sysno = 202;
pub const SYS_SETREUID: Sysno = 203;
pub const SYS_SETREGID: Sysno = 204;
pub const SYS_GETGROUPS: Sysno = 205;
pub const SYS_SETGROUPS: Sysno = 206;
pub const SYS_FCHOWN: Sysno = 207;
pub const SYS_SETRESUID: Sysno = 208;
pub const SYS_GETRESUID: Sysno = 209;
pub const SYS_SETRESGID: Sysno = 210;
pub const SYS_GETRESGID: Sysno = 211;
pub const SYS_CHOWN: Sysno = 212;
pub const SYS_SETUID: Sysno = 213;
pub const SYS_SETGID: Sysno = 214;
pub const SYS_SETFSUID: Sysno = 215;
pub const SYS_SETFSGID: Sysno = 216;
pub const SYS_PIVOT_ROOT: Sysno = 217;
pub const SYS_MINCORE: Sysno = 218;
pub const SYS_MADVISE: Sysno = 219;
pub const SYS_GETDENTS64: Sysno = 220;
pub const SYS_READAHEAD: Sysno = 222;
pub const SYS_SETXATTR: Sysno = 224;
pub const SYS_LSETXATTR: Sysno = 225;
pub const SYS_FSETXATTR: Sysno = 226;
pub const SYS_GETXATTR: Sysno = 227;
pub const SYS_LGETXATTR: Sysno = 228;
pub const SYS_FGETXATTR: Sysno = 229;
pub const SYS_LISTXATTR: Sysno = 230;
pub const SYS_LLISTXATTR: Sysno = 231;
pub const SYS_FLISTXATTR: Sysno = 232;
pub const SYS_REMOVEXATTR: Sysno = 233;
pub const SYS_LREMOVEXATTR: Sysno = 234;
pub const SYS_FREMOVEXATTR: Sysno = 235;
pub const SYS_GETTID: Sysno = 236;
pub const SYS_TKILL: Sysno = 237;
pub const SYS_FUTEX: Sysno = 238;
pub const SYS_SCHED_SETAFFINITY: Sysno = 239;
pub const SYS_SCHED_GETAFFINITY: Sysno = 240;
pub const SYS_TGKILL: Sysno = 241;
pub const SYS_IO_SETUP: Sysno = 243;
pub const SYS_IO_DESTROY: Sysno = 244;
pub const SYS_IO_GETEVENTS: Sysno = 245;
pub const SYS_IO_SUBMIT: Sysno = 246;
pub const SYS_IO_CANCEL: Sysno = 247;
pub const SYS_EXIT_GROUP: Sysno = 248;
pub const SYS_EPOLL_CREATE: Sysno = 249;
pub const SYS_EPOLL_CTL: Sysno = 250;
pub const SYS_EPOLL_WAIT: Sysno = 251;
pub const SYS_SET_TID_ADDRESS: Sysno = 252;
pub const SYS_FADVISE64: Sysno = 253;
pub const SYS_TIMER_CREATE: Sysno = 254;
pub const SYS_TIMER_SETTIME: Sysno = 255;
pub const SYS_TIMER_GETTIME: Sysno = 256;
pub const SYS_TIMER_GETOVERRUN: Sysno = 257;
pub const SYS_TIMER_DELETE: Sysno = 258;
pub const SYS_CLOCK_SETTIME: Sysno = 259;
pub const SYS_CLOCK_GETTIME: Sysno = 260;
pub const SYS_CLOCK_GETRES: Sysno = 261;
pub const SYS_CLOCK_NANOSLEEP: Sysno = 262;
pub const SYS_STATFS64: Sysno = 265;
pub const SYS_FSTATFS64: Sysno = 266;
pub const SYS_REMAP_FILE_PAGES: Sysno = 267;
pub const SYS_MBIND: Sysno = 268;
pub const SYS_GET_MEMPOLICY: Sysno = 269;
pub const SYS_SET_MEMPOLICY: Sysno = 270;
pub const SYS_MQ_OPEN: Sysno = 271;
pub const SYS_MQ_UNLINK: Sysno = 272;
pub const SYS_MQ_TIMEDSEND: Sysno = 273;
pub const SYS_MQ_TIMEDRECEIVE: Sysno = 274;
pub const SYS_MQ_NOTIFY: Sysno = 275;
pub const SYS_MQ_GETSETATTR: Sysno = 276;
pub const SYS_KEXEC_LOAD: Sysno = 277;
pub const SYS_ADD_KEY: Sysno = 278;
pub const SYS_REQUEST_KEY: Sysno = 279;
pub const SYS_KEYCTL: Sysno = 280;
pub const SYS_WAITID: Sysno = 281;
pub const SYS_IOPRIO_SET: Sysno = 282;
pub const SYS_IOPRIO_GET: Sysno = 283;
pub const SYS_INOTIFY_INIT: Sysno = 284;
pub const SYS_INOTIFY_ADD_WATCH: Sysno = 285;
pub const SYS_INOTIFY_RM_WATCH: Sysno = 286;
pub const SYS_MIGRATE_PAGES: Sysno = 287;
pub const SYS_OPENAT: Sysno = 288;
pub const SYS_MKDIRAT: Sysno = 289;
pub const SYS_MKNODAT: Sysno = 290;
pub const SYS_FCHOWNAT: Sysno = 291;
pub const SYS_FUTIMESAT: Sysno = 292;
pub const SYS_NEWFSTATAT: Sysno = 293;
pub const SYS_UNLINKAT: Sysno = 294;
pub const SYS_RENAMEAT: Sysno = 295;
pub const SYS_LINKAT: Sysno = 296;
pub const SYS_SYMLINKAT: Sysno = 297;
pub const SYS_READLINKAT: Sysno = 298;
pub const SYS_FCHMODAT: Sysno = 299;
pub const SYS_FACCESSAT: Sysno = 300;
pub const SYS_PSELECT6: Sysno = 301;
pub const SYS_PPOLL: Sysno = 302;
pub const SYS_UNSHARE: Sysno = 303;
pub const SYS_SET_ROBUST_LIST: Sysno = 304;
pub const SYS_GET_ROBUST_LIST: Sysno = 305;
pub const SYS_SPLICE: Sysno = 306;
pub const SYS_SYNC_FILE_RANGE: Sysno = 307;
pub const SYS_TEE: Sysno = 308;
pub const SYS_VMSPLICE: Sysno = 309;
pub const SYS_MOVE_PAGES: Sysno = 310;
pub const SYS_GETCPU: Sysno = 311;
pub const SYS_EPOLL_PWAIT: Sysno = 312;
pub const SYS_UTIMES: Sysno = 313;
pub const SYS_FALLOCATE: Sysno = 314;
pub const SYS_UTIMENSAT: Sysno = 315;
pub const SYS_SIGNALFD: Sysno = 316;
pub const SYS_TIMERFD: Sysno = 317;
pub const SYS_EVENTFD: Sysno = 318;
pub const SYS_TIMERFD_CREATE: Sysno = 319;
pub const SYS_TIMERFD_SETTIME: Sysno = 320;
pub const SYS_TIMERFD_GETTIME: Sysno = 321;
pub const SYS_SIGNALFD4: Sysno = 322;
pub const SYS_EVENTFD2: Sysno = 323;
pub const SYS_INOTIFY_INIT1: Sysno = 324;
pub const SYS_PIPE2: Sysno = 325;
pub const SYS_DUP3: Sysno = 326;
pub const SYS_EPOLL_CREATE1: Sysno = 327;
pub const SYS_PREADV: Sysno = 328;
pub const SYS_PWRITEV: Sysno = 329;
pub const SYS_RT_TGSIGQUEUEINFO: Sysno = 330;
pub const SYS_PERF_EVENT_OPEN: Sysno = 331;
pub const SYS_FANOTIFY_INIT: Sysno = 332;
pub const SYS_FANOTIFY_MARK: Sysno = 333;
pub const SYS_PRLIMIT64: Sysno = 334;
pub const SYS_NAME_TO_HANDLE_AT: Sysno = 335;
pub const SYS_OPEN_BY_HANDLE_AT: Sysno = 336;
pub const SYS_CLOCK_ADJTIME: Sysno = 337;
pub const SYS_SYNCFS: Sysno = 338;
pub const SYS_SETNS: Sysno = 339;
pub const SYS_PROCESS_VM_READV: Sysno = 340;
pub const SYS_PROCESS_VM_WRITEV: Sysno = 341;
pub const SYS_S390_RUNTIME_INSTR: Sysno = 342;
pub const SYS_KCMP: Sysno = 343;
pub const SYS_FINIT_MODULE: Sysno = 344;
pub const SYS_SCHED_SETATTR: Sysno = 345;
pub const SYS_SCHED_GETATTR: Sysno = 346;
pub const SYS_RENAMEAT2: Sysno = 347;
pub const SYS_SECCOMP: Sysno = 348;
pub const SYS_GETRANDOM: Sysno = 349;
pub const SYS_MEMFD_CREATE: Sysno = 350;
pub const SYS_BPF: Sysno = 351;
pub const SYS_S390_PCI_MMIO_WRITE: Sysno = 352;
pub const SYS_S390_PCI_MMIO_READ: Sysno = 353;
pub const SYS_EXECVEAT: Sysno = 354;
pub const SYS_USERFAULTFD: Sysno = 355;
pub const SYS_MEMBARRIER: Sysno = 356;
pub const SYS_RECVMMSG: Sysno = 357;
pub const SYS_SENDMMSG: Sysno = 358;
pub const SYS_SOCKET: Sysno = 359;
pub const SYS_SOCKETPAIR: Sysno = 360;
pub const SYS_BIND: Sysno = 361;
pub const SYS_CONNECT: Sysno = 362;
pub const SYS_LISTEN: Sysno = 363;
pub const SYS_ACCEPT4: Sysno = 364;
pub const SYS_GETSOCKOPT: Sysno = 365;
pub const SYS_SETSOCKOPT: Sysno = 366;
pub const SYS_GETSOCKNAME: Sysno = 367;
pub const SYS_GETPEERNAME: Sysno = 368;
pub const SYS_SENDTO: Sysno = 369;
pub const SYS_SENDMSG: Sysno = 370;
pub const SYS_RECVFROM: Sysno = 371;
pub const SYS_RECVMSG: Sysno = 372;
pub const SYS_SHUTDOWN: Sysno = 373;
pub const SYS_MLOCK2: Sysno = 374;
pub const SYS_COPY_FILE_RANGE: Sysno = 375;
pub const SYS_PREADV2: Sysno = 376;
pub const SYS_PWRITEV2: Sysno = 377;
pub const SYS_S390_GUARDED_STORAGE: Sysno = 378;
pub const SYS_STATX: Sysno = 379;
pub const SYS_S390_STHYI: Sysno = 380;
pub const SYS_KEXEC_FILE_LOAD: Sysno = 381;
pub const SYS_IO_PGETEVENTS: Sysno = 382;
pub const SYS_RSEQ: Sysno = 383;
pub const SYS_PKEY_MPROTECT: Sysno = 384;
pub const SYS_PKEY_ALLOC: Sysno = 385;
pub const SYS_PKEY_FREE: Sysno = 386;
pub const SYS_SEMTIMEDOP: Sysno = 392;
pub const SYS_SEMGET: Sysno = 393;
pub const SYS_SEMCTL: Sysno = 394;
pub const SYS_SHMGET: Sysno = 395;
pub const SYS_SHMCTL: Sysno = 396;
pub const SYS_SHMAT: Sysno = 397;
pub const SYS_SHMDT: Sysno = 398;
pub const SYS_MSGGET: Sysno = 399;
pub const SYS_MSGSND: Sysno = 400;
pub const SYS_MSGRCV: Sysno = 401;
pub const SYS_MSGCTL: Sysno = 402;
pub const SYS_PIDFD_SEND_SIGNAL: Sysno = 424;
pub const SYS_IO_URING_SETUP: Sysno = 425;
pub const SYS_IO_URING_ENTER: Sysno = 426;
pub const SYS_IO_URING_REGISTER: Sysno = 427;
pub const SYS_OPEN_TREE: Sysno = 428;
pub const SYS_MOVE_MOUNT: Sysno = 429;
pub const SYS_FSOPEN: Sysno = 430;
pub const SYS_FSCONFIG: Sysno = 431;
pub const SYS_FSMOUNT: Sysno = 432;
pub const SYS_FSPICK: Sysno = 433;
pub const SYS_PIDFD_OPEN: Sysno = 434;
pub const SYS_CLONE3: Sysno = 435;
pub const SYS_CLOSE_RANGE: Sysno = 436;
pub const SYS_OPENAT2: Sysno = 437;
pub const SYS_PIDFD_GETFD: Sysno = 438;
pub const SYS_FACCESSAT2: Sysno = 439;
pub const SYS_PROCESS_MADVISE: Sysno = 440;
pub const SYS_EPOLL_PWAIT2: Sysno = 441;
pub const SYS_MOUNT_SETATTR: Sysno = 442;
pub const SYS_QUOTACTL_FD: Sysno = 443;
pub const SYS_LANDLOCK_CREATE_RULESET: Sysno = 444;
pub const SYS_LANDLOCK_ADD_RULE: Sysno = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: Sysno = 446;
pub const SYS_MEMFD_SECRET: Sysno = 447;
pub const SYS_PROCESS_MRELEASE: Sysno = 448;
pub const SYS_FUTEX_WAITV: Sysno = 449;
pub const SYS_SET_MEMPOLICY_HOME_NODE: Sysno = 450;
pub const SYS_CACHESTAT: Sysno = 451;
pub const SYS_FCHMODAT2: Sysno = 452;
pub const SYS_MAP_SHADOW_STACK: Sysno = 453;
pub const SYS_FUTEX_WAKE: Sysno = 454;
pub const SYS_FUTEX_WAIT: Sysno = 455;
pub const SYS_FUTEX_REQUEUE: Sysno = 456;
pub const SYS_STATMOUNT: Sysno = 457;
pub const SYS_LISTMOUNT: Sysno = 458;
pub const SYS_LSM_GET_SELF_ATTR: Sysno = 459;
pub const SYS_LSM_SET_SELF_ATTR: Sysno = 460;
pub const SYS_LSM_LIST_MODULES: Sysno = 461;
pub const SYS_MSEAL: Sysno = 462;


use super::types::{mode_t, key_t};

/// open() mode
pub const S_IRUSR: mode_t = 0o400;
pub const S_IWUSR: mode_t = 0o200;
pub const S_IXUSR: mode_t = 0o100;
pub const S_IRWXU: mode_t = S_IRUSR | S_IWUSR | S_IXUSR;
pub const S_IRGRP: mode_t = S_IRUSR >> 3;
pub const S_IWGRP: mode_t = S_IWUSR >> 3;
pub const S_IXGRP: mode_t = S_IXUSR >> 3;
pub const S_IRWXG: mode_t = S_IRWXU >> 3;
pub const S_IROTH: mode_t = S_IRGRP >> 3;
pub const S_IWOTH: mode_t = S_IWGRP >> 3;
pub const S_IXOTH: mode_t = S_IXGRP >> 3;
pub const S_IRWXO: mode_t = S_IRWXG >> 3;

/// open() flags
pub const O_RDONLY:     i32 = 0o0;
pub const O_WRONLY:     i32 = 0o1;
pub const O_RDWR:       i32 = 0o2;
pub const O_ACCMODE:    i32 = 0o003;
pub const O_CREAT:      i32 = 0o100;
pub const O_EXCL:       i32 = 0o200;
pub const O_NOCTTY:     i32 = 0o400;
pub const O_TRUNC:      i32 = 0o1000;
pub const O_APPEND:     i32 = 0o2000;
pub const O_NONBLOCK:   i32 = 0o4000;
pub const O_DSYNC:      i32 = 0o10000;
pub const O_ASYNC:      i32 = 0o20000;
pub const O_DIRECT:     i32 = 0o40000;
pub const O_LARGEFILE:  i32 = 0o100000;
pub const O_DIRECTORY:  i32 = 0o200000;
pub const O_NOFOLLOW:   i32 = 0o400000;
pub const O_NOATIME:    i32 = 0o1000000;
pub const O_CLOEXEC:    i32 = 0o2000000;
pub const O_SYNC:       i32 = 0o4010000;
pub const O_FSYNC:      i32 = O_SYNC;
pub const O_PATH:       i32 = 0o10000000;
pub const O_TMPFILE:    i32 = (0o20000000 | O_DIRECTORY);

/// access() mode
pub const R_OK: i32 = 4;
pub const W_OK: i32 = 2;
pub const X_OK: i32 = 1;
pub const F_OK: i32 = 0;

/// sync_file_range() mode
pub const SYNC_FILE_RANGE_WAIT_BEFORE: i32 = 1;
pub const SYNC_FILE_RANGE_WRITE:       i32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER:  i32 = 4;

pub const SPLICE_F_MOVE:     i32 = 1;
pub const SPLICE_F_NONBLOCK: i32 = 2;
pub const SPLICE_F_MORE:     i32 = 4;
pub const SPLICE_F_GIFT:     i32 = 8;

pub const SIG_BLOCK:   i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// Signals
pub const SIGHUP:    i32 = 1;
pub const SIGINT:    i32 = 2;
pub const SIGQUIT:   i32 = 3;
pub const SIGILL:    i32 = 4;
pub const SIGTRAP:   i32 = 5;
pub const SIGABRT:   i32 = 6;
pub const SIGIOT:    i32 = 6;
pub const SIGBUS:    i32 = 7;
pub const SIGFPE:    i32 = 8;
pub const SIGKILL:   i32 = 9;
pub const SIGUSR1:   i32 = 10;
pub const SIGSEGV:   i32 = 11;
pub const SIGUSR2:   i32 = 12;
pub const SIGPIPE:   i32 = 13;
pub const SIGALRM:   i32 = 14;
pub const SIGTERM:   i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD:   i32 = 17;
pub const SIGCONT:   i32 = 18;
pub const SIGSTOP:   i32 = 19;
pub const SIGTSTP:   i32 = 20;
pub const SIGTTIN:   i32 = 21;
pub const SIGTTOU:   i32 = 22;
pub const SIGURG:    i32 = 23;
pub const SIGXCPU:   i32 = 24;
pub const SIGXFSZ:   i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF:   i32 = 27;
pub const SIGWINCH:  i32 = 28;
pub const SIGIO:     i32 = 29;
pub const SIGPOLL:   i32 = 29;
pub const SIGPWR:    i32 = 30;
pub const SIGSYS:    i32 = 31;
pub const SIGUNUSED: i32 = 31;

pub const SIG_RT_MIN: i32 = 32;
pub const SIG_RTMAX:  i32 = 64;

/// sigaction() sa_flags
pub const SA_NOCLDSTOP: i32 = 1;
pub const SA_NOCLDWAIT: i32 = 2;
pub const SA_SIGINFO:   i32 = 4;
pub const SA_ONSTACK:   i32 = 0x08000000;
pub const SA_RESTART:   i32 = 0x10000000;
pub const SA_INTERRUPT: i32 = 0x20000000;
pub const SA_NODEFER:   i32 = 0x40000000;
#[allow(overflowing_literals)]
pub const SA_RESETHAND: i32 = 0x80000000;

/// lseek() whence
pub const SEEK_SET:  i32 = 0; // seek relative to beginning of file
pub const SEEK_CUR:  i32 = 1; // seek relative to current file position
pub const SEEK_END:  i32 = 2; // seek relative to end of file
pub const SEEK_DATA: i32 = 3; // seek to the next data
pub const SEEK_HOLE: i32 = 4; // seek to the next hole
pub const SEEK_MAX:  i32 = SEEK_HOLE;

pub const RENAME_NOREPLACE: i32 = 1; // Don't overwrite target
pub const RENAME_EXCHANGE:  i32 = 2; // Exchange source and dest
pub const RENAME_WHITEOUT:  i32 = 4; // Whiteout source

/// Poll event
pub const POLLIN:     i32 = 0x001;
pub const POLLPRI:    i32 = 0x002;
pub const POLLOUT:    i32 = 0x004;
pub const POLLERR:    i32 = 0x008;
pub const POLLHUP:    i32 = 0x010;
pub const POLLNVAL:   i32 = 0x020;
pub const POLLRDNORM: i32 = 0x040;
pub const POLLRDBAND: i32 = 0x080;
pub const POLLWRNORM: i32 = 0x100;
pub const POLLWRBAND: i32 = 0x200;

/// Mmap protection types
pub const PROT_NONE:      i32 = 0x0;
pub const PROT_READ:      i32 = 0x1;
pub const PROT_WRITE:     i32 = 0x2;
pub const PROT_EXEC:      i32 = 0x4;
pub const PROT_GROWSDOWN: i32 = 0x01000000;
pub const PROT_GROWSUP:   i32 = 0x02000000;

/// Mmap flags
pub const MAP_UNINITIALIZED:   i32 = 0x00;
pub const MAP_SHARED:          i32 = 0x01;
pub const MAP_PRIVATE:         i32 = 0x02;
pub const MAP_SHARED_VALIDATE: i32 = 0x03;
pub const MAP_TYPE:            i32 = 0x0f;
pub const MAP_FIXED:           i32 = 0x10;
pub const MAP_ANONYMOUS:       i32 = 0x20;
pub const MAP_GROWSDOWN:       i32 = 0x0100;
pub const MAP_DENYWRITE:       i32 = 0x0800;
pub const MAP_EXECUTABLE:      i32 = 0x1000;
pub const MAP_LOCKED:          i32 = 0x2000;
pub const MAP_NORESERVE:       i32 = 0x4000;
pub const MAP_POPULATE:        i32 = 0x8000;
pub const MAP_NONBLOCK:        i32 = 0x10000;
pub const MAP_STACK:           i32 = 0x20000;
pub const MAP_HUGETLB:         i32 = 0x40000;
pub const MAP_SYNC:            i32 = 0x80000;
pub const MAP_FIXED_NOREPLACE: i32 = 0x100000;

pub const MAP_FAILED: i32 = -1;

/// Mmap lock
pub const MCL_CURRENT: i32 = 1;
pub const MCL_FUTURE:  i32 = 2;
pub const MCL_ONFAULT: i32 = 4;

/// msync flags
pub const MS_ASYNC:      i32 = 1;
pub const MS_SYNC:       i32 = 4;
pub const MS_INVALIDATE: i32 = 2;

/// Mode bits for `msgget', `semget', and `shmget'.
pub const IPC_CREAT:  i32 = 0o1000;
pub const IPC_EXCL:   i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;

/// Control commands for `msgctl', `semctl', and `shmctl'. 
pub const IPC_RMID: i32 = 0;
pub const IPC_SET:  i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

pub const IPC_PRIVATE: key_t = 0;

/// msgrcv options
pub const MSG_NOERROR: i32 = 010000; // No error if message is too big.
pub const MSG_EXCEPT:  i32 = 020000; // Recv any msg except of specified type.
pub const MSG_COPY:    i32 = 040000; // Copy (not remove) all queue messages.

/// ipcs ctl commands
pub const MSG_STAT:     i32 = 11;
pub const MSG_INFO:     i32 = 12;
pub const MSG_STAT_ANY: i32 = 13;

/// Socket types
pub const SOCK_STREAM:    i32 = 1;
pub const SOCK_DGRAM:     i32 = 2;
pub const SOCK_RAW:       i32 = 3;
pub const SOCK_RDM:       i32 = 4;
pub const SOCK_SEQPACKET: i32 = 5;
pub const SOCK_DCCP:      i32 = 6;
pub const SOCK_PACKET:    i32 = 10;
pub const SOCK_CLOEXEC:   i32 = 0o2000000;
pub const SOCK_NONBLOCK:  i32 = 0o0004000;

// socket domain
pub const PF_UNSPEC:        i32 = 0;
pub const PF_LOCAL:         i32 = 1;
pub const PF_UNIX:          i32 = PF_LOCAL;
pub const PF_FILE:          i32 = PF_LOCAL;
pub const PF_INET:          i32 = 2;
pub const PF_AX25:          i32 = 3;
pub const PF_IPX:           i32 = 4;
pub const PF_APPLETALK:     i32 = 5;
pub const PF_NETROM:        i32 = 6;
pub const PF_BRIDGE:        i32 = 7;
pub const PF_ATMPVC:        i32 = 8;
pub const PF_X25:           i32 = 9;
pub const PF_INET6:         i32 = 10;
pub const PF_ROSE:          i32 = 11;
#[allow(non_upper_case_globals)]
pub const PF_DECnet:        i32 = 12;
pub const PF_NETBEUI:       i32 = 13;
pub const PF_SECURITY:      i32 = 14;
pub const PF_KEY:           i32 = 15;
pub const PF_NETLINK:       i32 = 16;
pub const PF_ROUTE:         i32 = PF_NETLINK;
pub const PF_PACKET:        i32 = 17;
pub const PF_ASH:           i32 = 18;
pub const PF_ECONET:        i32 = 19;
pub const PF_ATMSVC:        i32 = 20;
pub const PF_RDS:           i32 = 21;
pub const PF_SNA:           i32 = 22;
pub const PF_IRDA:          i32 = 23;
pub const PF_PPPOX:         i32 = 24;
pub const PF_WANPIPE:       i32 = 25;
pub const PF_LLC:           i32 = 26;
pub const PF_IB:            i32 = 27;
pub const PF_MPLS:          i32 = 28;
pub const PF_CAN:           i32 = 29;
pub const PF_TIPC:          i32 = 30;
pub const PF_BLUETOOTH:     i32 = 31;
pub const PF_IUCV:          i32 = 32;
pub const PF_RXRPC:         i32 = 33;
pub const PF_ISDN:          i32 = 34;
pub const PF_PHONET:        i32 = 35;
pub const PF_IEEE802154:    i32 = 36;
pub const PF_CAIF:          i32 = 37;
pub const PF_ALG:           i32 = 38;
pub const PF_NFC:           i32 = 39;
pub const PF_VSOCK:         i32 = 40;
pub const PF_KCM:           i32 = 41;
pub const PF_QIPCRTR:       i32 = 42;
pub const PF_SMC:           i32 = 43;
pub const PF_MAX:           i32 = 44;

pub const AF_UNSPEC:        i32 = PF_UNSPEC;
pub const AF_LOCAL:         i32 = PF_LOCAL;
pub const AF_UNIX:          i32 = PF_UNIX;
pub const AF_FILE:          i32 = PF_FILE;
pub const AF_INET:          i32 = PF_INET;
pub const AF_AX25:          i32 = PF_AX25;
pub const AF_IPX:           i32 = PF_IPX;
pub const AF_APPLETALK:     i32 = PF_APPLETALK;
pub const AF_NETROM:        i32 = PF_NETROM;
pub const AF_BRIDGE:        i32 = PF_BRIDGE;
pub const AF_ATMPVC:        i32 = PF_ATMPVC;
pub const AF_X25:           i32 = PF_X25;
pub const AF_INET6:         i32 = PF_INET6;
pub const AF_ROSE:          i32 = PF_ROSE;
#[allow(non_upper_case_globals)]
pub const AF_DECnet:        i32 = PF_DECnet;
pub const AF_NETBEUI:       i32 = PF_NETBEUI;
pub const AF_SECURITY:      i32 = PF_SECURITY;
pub const AF_KEY:           i32 = PF_KEY;
pub const AF_NETLINK:       i32 = PF_NETLINK;
pub const AF_ROUTE:         i32 = PF_ROUTE;
pub const AF_PACKET:        i32 = PF_PACKET;
pub const AF_ASH:           i32 = PF_ASH;
pub const AF_ECONET:        i32 = PF_ECONET;
pub const AF_ATMSVC:        i32 = PF_ATMSVC;
pub const AF_RDS:           i32 = PF_RDS;
pub const AF_SNA:           i32 = PF_SNA;
pub const AF_IRDA:          i32 = PF_IRDA;
pub const AF_PPPOX:         i32 = PF_PPPOX;
pub const AF_WANPIPE:       i32 = PF_WANPIPE;
pub const AF_LLC:           i32 = PF_LLC;
pub const AF_IB:            i32 = PF_IB;
pub const AF_MPLS:          i32 = PF_MPLS;
pub const AF_CAN:           i32 = PF_CAN;
pub const AF_TIPC:          i32 = PF_TIPC;
pub const AF_BLUETOOTH:     i32 = PF_BLUETOOTH;
pub const AF_IUCV:          i32 = PF_IUCV;
pub const AF_RXRPC:         i32 = PF_RXRPC;
pub const AF_ISDN:          i32 = PF_ISDN;
pub const AF_PHONET:        i32 = PF_PHONET;
pub const AF_IEEE802154:    i32 = PF_IEEE802154;
pub const AF_CAIF:          i32 = PF_CAIF;
pub const AF_ALG:           i32 = PF_ALG;
pub const AF_NFC:           i32 = PF_NFC;
pub const AF_VSOCK:         i32 = PF_VSOCK;
pub const AF_KCM:           i32 = PF_KCM;
pub const AF_QIPCRTR:       i32 = PF_QIPCRTR;
pub const AF_SMC:           i32 = PF_SMC;
pub const AF_MAX:           i32 = PF_MAX;

/// Standard well-defined IP protocols.
pub const IPPROTO_IP:       i32 = 0; // Dummy protocol for TCP
pub const IPPROTO_ICMP:     i32 = 1; // Internet Control Message Protocol
pub const IPPROTO_IGMP:     i32 = 2; // Internet Group Management Protocol
pub const IPPROTO_IPIP:     i32 = 4; // IPIP tunnels (older KA9Q tunnels use 94)
pub const IPPROTO_TCP:      i32 = 6; // Transmission Control Protocol
pub const IPPROTO_EGP:      i32 = 8; // Exterior Gateway Protocol
pub const IPPROTO_PUP:      i32 = 12; // PUP protocol
pub const IPPROTO_UDP:      i32 = 17; // User Datagram Protocol
pub const IPPROTO_IDP:      i32 = 22; // XNS IDP protocol
pub const IPPROTO_TP:       i32 = 29; // SO Transport Protocol Class 4
pub const IPPROTO_DCCP:     i32 = 33; // Datagram Congestion Control Protocol
pub const IPPROTO_IPV6:     i32 = 41; // IPv6-in-IPv4 tunnelling
pub const IPPROTO_RSVP:     i32 = 46; // RSVP Protocol
pub const IPPROTO_GRE:      i32 = 47; // Cisco GRE tunnels (rfc 1701,1702)
pub const IPPROTO_ESP:      i32 = 50; // Encapsulation Security Payload protocol
pub const IPPROTO_AH:       i32 = 51; // Authentication Header protocol
pub const IPPROTO_MTP:      i32 = 92; // Multicast Transport Protocol
pub const IPPROTO_BEETPH:   i32 = 94; // IP option pseudo header for BEET
pub const IPPROTO_ENCAP:    i32 = 98; // Encapsulation Header
pub const IPPROTO_PIM:      i32 = 103; // Protocol Independent Multicast
pub const IPPROTO_COMP:     i32 = 108; // Compression Header Protocol
pub const IPPROTO_SCTP:     i32 = 132; // Stream Control Transport Protocol
pub const IPPROTO_UDPLITE:  i32 = 136; // UDP-Lite (RFC 3828)
pub const IPPROTO_MPLS:     i32 = 137; // MPLS in IP (RFC 4023)
pub const IPPROTO_RAW:      i32 = 255; // Raw IP packets
pub const IPPROTO_MAX:      i32 = 256;

pub const IP_TOS:                   i32 = 1;
pub const IP_TTL:                   i32 = 2;
pub const IP_HDRINCL:               i32 = 3;
pub const IP_OPTIONS:               i32 = 4;
pub const IP_ROUTER_ALERT:          i32 =5;
pub const IP_RECVOPTS:              i32 = 6;
pub const IP_RETOPTS:               i32 = 7;
pub const IP_PKTINFO:               i32 = 8;
pub const IP_PKTOPTIONS:            i32 = 9;
pub const IP_MTU_DISCOVER:          i32 = 10;
pub const IP_RECVERR:               i32 = 11;
pub const IP_RECVTTL:               i32 = 12;
pub const IP_RECVTOS:               i32 = 13;
pub const IP_MTU:                   i32 = 14;
pub const IP_FREEBIND:              i32 = 15;
pub const IP_IPSEC_POLICY:          i32 = 16;
pub const IP_XFRM_POLICY:           i32 = 17;
pub const IP_PASSSEC:               i32 = 18;
pub const IP_TRANSPARENT:           i32 = 19;
pub const IP_RECVRETOPTS:           i32 = IP_RETOPTS;
pub const IP_ORIGDSTADDR:           i32 = 20;
pub const IP_RECVORIGDSTADDR:       i32 = IP_ORIGDSTADDR;
pub const IP_MINTTL:                i32 = 21;
pub const IP_NODEFRAG:              i32 = 22;
pub const IP_CHECKSUM:              i32 = 23;
pub const IP_BIND_ADDRESS_NO_PORT:  i32 = 24;
pub const IP_RECVFRAGSIZE:          i32 = 25;

/// Operations for the `flock` call.
pub const LOCK_SH:      i32 = 1;  // Shared lock.
pub const LOCK_EX:      i32 = 2;  // Exclusive lock.
pub const LOCK_UN:      i32 = 8;  // Unlock.
pub const LOCK_ATOMIC:  i32 = 16; // Atomic update.

pub const AT_FDCWD:              i32 = -100;
pub const AT_SYMLINK_NOFOLLOW:   i32 = 0x100;
pub const AT_REMOVEDIR:          i32 = 0x200;
pub const AT_EACCESS:            i32 = 0x200;
pub const AT_SYMLINK_FOLLOW:     i32 = 0x400;
pub const AT_NO_AUTOMOUNT:       i32 = 0x800;
pub const AT_EMPTY_PATH:         i32 = 0x1000;
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
pub const AT_STATX_FORCE_SYNC:   i32 = 0x2000;
pub const AT_STATX_DONT_SYNC:    i32 = 0x4000;
pub const AT_STATX_SYNC_TYPE:    i32 = 0x6000;

/// Magic values required to use `reboot` system call.
#[allow(overflowing_literals)]
pub const LINUX_REBOOT_MAGIC1:  i32 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2:  i32 = 672274793;
pub const LINUX_REBOOT_MAGIC2A: i32 = 85072278;
pub const LINUX_REBOOT_MAGIC2B: i32 = 369367448;
pub const LINUX_REBOOT_MAGIC2C: i32 = 537993216;

/// Commands accepted by the _reboot() system call.
/// RESTART     Restart system using default command and mode.
/// HALT        Stop OS and give system control to ROM monitor, if any.
/// CAD_ON      Ctrl-Alt-Del sequence causes RESTART command.
/// CAD_OFF     Ctrl-Alt-Del sequence sends SIGINT to init task.
/// POWER_OFF   Stop OS and remove all power from system, if possible.
/// RESTART2    Restart system using given command string.
/// SW_SUSPEND  Suspend system using software suspend if compiled in.
/// KEXEC       Restart system using a previously loaded Linux kernel
pub const LINUX_REBOOT_CMD_RESTART:    u32 = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT:       u32 = 0xCDEF0123;
pub const LINUX_REBOOT_CMD_CAD_ON:     u32 = 0x89ABCDEF;
pub const LINUX_REBOOT_CMD_CAD_OFF:    u32 = 0x00000000;
pub const LINUX_REBOOT_CMD_POWER_OFF:  u32 = 0x4321FEDC;
pub const LINUX_REBOOT_CMD_RESTART2:   u32 = 0xA1B2C3D4;
pub const LINUX_REBOOT_CMD_SW_SUSPEND: u32 = 0xD000FCE2;
pub const LINUX_REBOOT_CMD_KEXEC:      u32 = 0x45584543;

/// Kinds of resource limit
pub const RLIMIT_CPU:        i32 = 0; // Per-process CPU limit, in seconds.
pub const RLIMIT_FSIZE:      i32 = 1; // Largest file that can be created, in bytes.
pub const RLIMIT_DATA:       i32 = 2; // Maximum size of data segment, in bytes.
pub const RLIMIT_STACK:      i32 = 3; // Maximum size of stack segment, in bytes.
pub const RLIMIT_CORE:       i32 = 4; // Largest core file that can be created, in bytes.
pub const RLIMIT_RSS:        i32 = 5; // Largest resident set size, in bytes.
pub const RLIMIT_NPROC:      i32 = 6; // Number of processes.
pub const RLIMIT_NOFILE:     i32 = 7; // Number of open files.
pub const RLIMIT_AS:         i32 = 9; // Address space limit.
pub const RLIMIT_MEMLOCK:    i32 = 8; // Locked-in-memory address space.
pub const RLIMIT_LOCKS:      i32 = 10; // Maximum number of file locks.
pub const RLIMIT_SIGPENDING: i32 = 11; // Maximum number of pending signals.
pub const RLIMIT_MSGQUEUE:   i32 = 12; // Maximum bytes in POSIX message queues.
pub const RLIMIT_NICE:       i32 = 13; // Maximum nice priority allowed to raise to.
pub const RLIMIT_RTPRIO:     i32 = 14; // Maximum realtime priority
pub const RLIMIT_RTTIME:     i32 = 15; // Maximum CPU time in µs for RT tasks.
pub const RLIMIT_NLIMITS:    i32 = 16;

/// Actions used in `syslog()`.
pub const SYSLOG_ACTION_CLOSE:         i32 = 0; // Close the log.  Currently a NOP.
pub const SYSLOG_ACTION_OPEN:          i32 = 1; // Open the log. Currently a NOP.
pub const SYSLOG_ACTION_READ:          i32 = 2; // Read from the log.
pub const SYSLOG_ACTION_READ_ALL:      i32 = 3; // Read all messages remaining in the ring buffer.
pub const SYSLOG_ACTION_READ_CLEAR:    i32 = 4; // Read and clear all messages remaining in the ring buffer
pub const SYSLOG_ACTION_CLEAR:         i32 = 5; // Clear ring buffer.
pub const SYSLOG_ACTION_CONSOLE_OFF:   i32 = 6; // Disable printk's to console
pub const SYSLOG_ACTION_CONSOLE_ON:    i32 = 7; // Enable printk's to console
pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8; // Set level of messages printed to console
pub const SYSLOG_ACTION_SIZE_UNREAD:   i32 = 9; // Return number of unread characters in the log buffer
pub const SYSLOG_ACTION_SIZE_BUFFER:   i32 = 10; // Return size of the log buffer

pub const SYSLOG_FROM_READER: i32 = 0;
pub const SYSLOG_FROM_PROC:   i32 = 1;

/// Priority limits.
pub const PRIO_MIN: i32 = -20; // Minimum priority a process can have.
pub const PRIO_MAX: i32 = 20;  // Maximum priority a process can have.

/// The type of the `which` argument to `getpriority` and `setpriority`.
pub const PRIO_PROCESS: i32 = 0; // WHO is a process ID.
pub const PRIO_PGRP:    i32 = 1; // WHO is a process group ID.
pub const PRIO_USER:    i32 = 2; // WHO is a user ID.

pub const CTL_MAXNAME: i32 = 10; // how many path components do we allow in a call to sysctl

/// `sysctl` names
pub const CTL_KERN:    i32 = 1;    // General kernel info and control
pub const CTL_VM:      i32 = 2;    // VM management
pub const CTL_NET:     i32 = 3;    // Networking
pub const CTL_PROC:    i32 = 4;    // removal breaks strace(1) compilation
pub const CTL_FS:      i32 = 5;    // Filesystems
pub const CTL_DEBUG:   i32 = 6;    // Debugging
pub const CTL_DEV:     i32 = 7;    // Devices
pub const CTL_BUS:     i32 = 8;    // Busses
pub const CTL_ABI:     i32 = 9;    // Binary emulation
pub const CTL_CPU:     i32 = 10;   // CPU stuff (speed scaling, etc)
pub const CTL_ARLAN:   i32 = 254;  // arlan wireless driver
pub const CTL_S390DBF: i32 = 5677; // s390 debug
pub const CTL_SUNRPC:  i32 = 7249; // sunrpc debug
pub const CTL_PM:      i32 = 9899; // frv power management
pub const CTL_FRV:     i32 = 9898; // frv specific sysctls

/// CTL_BUS names:
pub const CTL_BUS_ISA: i32 = 1; // ISA

/// Values to pass as first argument to `prctl`.
pub const PR_SET_PDEATHSIG:            i32 = 1; // Second arg is a signal
pub const PR_GET_PDEATHSIG:            i32 = 2; // Second arg is a ptr to return the signal
pub const PR_GET_DUMPABLE:             i32 = 3; // Get current->mm->dumpable
pub const PR_SET_DUMPABLE:             i32 = 4; // Set current->mm->dumpable
pub const PR_GET_UNALIGN:              i32 = 5; // Get unaligned access control bits (if meaningful)
pub const PR_SET_UNALIGN:              i32 = 6; // Set unaligned access control bits (if meaningful)
pub const PR_GET_KEEPCAPS:             i32 = 7; // Get whether or not to drop capabilities on setuid() away from uid 0
pub const PR_SET_KEEPCAPS:             i32 = 8;  // Set whether or not to drop capabilities on setuid() away from uid 0
pub const PR_GET_FPEMU:                i32 = 9; // Get floating-point emulation control bits (if meaningful)
pub const PR_SET_FPEMU:                i32 = 10; // Set floating-point emulation control bits (if meaningful)
pub const PR_GET_FPEXC:                i32 = 11; // Get floating-point exception mode (if meaningful)
pub const PR_SET_FPEXC:                i32 = 12; // Get floating-point exception mode (if meaningful)
pub const PR_GET_TIMING:               i32 = 13; // Get whether use statistical/accurate process timing
pub const PR_SET_TIMING:               i32 = 14; // Get whether use statistical/accurate process timing
pub const PR_SET_NAME:                 i32 = 15; // Set process name
pub const PR_GET_NAME:                 i32 = 16; // Get process name
pub const PR_GET_ENDIAN:               i32 = 19; // Get process endian
pub const PR_SET_ENDIAN:               i32 = 20; // Set process endian
pub const PR_GET_SECCOMP:              i32 = 21; // Get process seccomp mode
pub const PR_SET_SECCOMP:              i32 = 22; // Set process seccomp mode
pub const PR_CAPBSET_READ:             i32 = 23; // Get the capability bounding set
pub const PR_CAPBSET_DROP:             i32 = 24; // Set the capability bounding set
pub const PR_GET_TSC:                  i32 = 25; // Get the process' ability to use the timestamp counter instruction
pub const PR_SET_TSC:                  i32 = 26; // Set the process' ability to use the timestamp counter instruction
pub const PR_GET_SECUREBITS:           i32 = 27; // Get securebits (as per security/commoncap.c)
pub const PR_SET_SECUREBITS:           i32 = 28; // Set securebits (as per security/commoncap.c)
pub const PR_SET_TIMERSLACK:           i32 = 29; // Set the timerslack as used by poll/select/nanosleep
pub const PR_GET_TIMERSLACK:           i32 = 30; // Get the timerslack as used by poll/select/nanosleep
pub const PR_TASK_PERF_EVENTS_DISABLE: i32 = 31;
pub const PR_TASK_PERF_EVENTS_ENABLE:  i32 = 32;
pub const PR_MCE_KILL:                 i32 = 33; // Set early/late kill mode for hwpoison memory corruption.
pub const PR_MCE_KILL_GET:             i32 = 34;
pub const PR_SET_MM:                   i32 = 35;

pub const PR_UNALIGN_NOPRINT: i32 = 1; // silently fix up unaligned user accesses
pub const PR_UNALIGN_SIGBUS:  i32 = 2; // generate SIGBUS on unaligned user access

pub const PR_FPEMU_NOPRINT: i32 = 1; // silently emulate fp operations accesses
pub const PR_FPEMU_SIGFPE:  i32 = 2; // don't emulate fp operations, send SIGFPE instead

pub const PR_FP_EXC_DISABLED:  i32 = 0; // FP exceptions disabled
pub const PR_FP_EXC_NONRECOV:  i32 = 1; // async non-recoverable exc. mode 
pub const PR_FP_EXC_ASYNC:     i32 = 2; // async recoverable exception mode
pub const PR_FP_EXC_PRECISE:   i32 = 3; // precise exception mode
pub const PR_FP_EXC_SW_ENABLE: i32 = 0x80; // Use FPEXC for FP exception enables
pub const PR_FP_EXC_DIV:       i32 = 0x010000; // floating point divide by zero
pub const PR_FP_EXC_OVF:       i32 = 0x020000; // floating point overflow
pub const PR_FP_EXC_UND:       i32 = 0x040000; // floating point underflow
pub const PR_FP_EXC_RES:       i32 = 0x080000; // floating point inexact result
pub const PR_FP_EXC_INV:       i32 = 0x100000; // floating point invalid operation

pub const PR_TIMING_STATISTICAL: i32 = 0; // Normal, traditional, statistical process timing
pub const PR_TIMING_TIMESTAMP:   i32 = 1; // Accurate timestamp based process timing

pub const PR_ENDIAN_BIG:        i32 = 0;
pub const PR_ENDIAN_LITTLE:     i32 = 1; // True little endian mode
pub const PR_ENDIAN_PPC_LITTLE: i32 = 2; // "PowerPC" pseudo little endian

pub const PR_TSC_ENABLE:  i32 = 1; // allow the use of the timestamp counter
pub const PR_TSC_SIGSEGV: i32 = 2; // throw a SIGSEGV instead of reading the TSC


pub const PR_MCE_KILL_CLEAR: i32 = 0;
pub const PR_MCE_KILL_SET:   i32 = 1;

pub const PR_MCE_KILL_LATE:    i32 = 0;
pub const PR_MCE_KILL_EARLY:   i32 = 1;
pub const PR_MCE_KILL_DEFAULT: i32 = 2;

/// Tune up process memory map specifics.
pub const PR_SET_MM_START_CODE:  i32 = 1;
pub const PR_SET_MM_END_CODE:    i32 = 2;
pub const PR_SET_MM_START_DATA:  i32 = 3;
pub const PR_SET_MM_END_DATA:    i32 = 4;
pub const PR_SET_MM_START_STACK: i32 = 5;
pub const PR_SET_MM_START_BRK:   i32 = 6;
pub const PR_SET_MM_BRK:         i32 = 7;
pub const PR_SET_MM_ARG_START:   i32 = 8;
pub const PR_SET_MM_ARG_END:     i32 = 9;
pub const PR_SET_MM_ENV_START:   i32 = 10;
pub const PR_SET_MM_ENV_END:     i32 = 11;
pub const PR_SET_MM_AUXV:        i32 = 12;
pub const PR_SET_MM_EXE_FILE:    i32 = 13;
pub const PR_SET_MM_MAP:         i32 = 14;
pub const PR_SET_MM_MAP_SIZE:    i32 = 15;


/// Mode codes (timex_t.mode)
pub const ADJ_OFFSET:    i32 = 0x0001; // time offset
pub const ADJ_FREQUENCY: i32 = 0x0002; // frequency offset
pub const ADJ_MAXERROR:  i32 = 0x0004; // maximum time error
pub const ADJ_ESTERROR:  i32 = 0x0008; // estimated time error
pub const ADJ_STATUS:    i32 = 0x0010; // clock status
pub const ADJ_TIMECONST: i32 = 0x0020; // pll time constant
pub const ADJ_TAI:       i32 = 0x0080; // set TAI offset
pub const ADJ_SETOFFSET: i32 = 0x0100; // add 'time' to current time
pub const ADJ_MICRO:     i32 = 0x1000; // select microsecond resolution
pub const ADJ_NANO:      i32 = 0x2000; // select nanosecond resolution
pub const ADJ_TICK:      i32 = 0x4000; // tick value

/// Status codes (timex_t.status)
pub const STA_PLL:       i32 = 0x0001; // enable PLL updates (rw)
pub const STA_PPSFREQ:   i32 = 0x0002; // enable PPS freq discipline (rw)
pub const STA_PPSTIME:   i32 = 0x0004; // enable PPS time discipline (rw)
pub const STA_FLL:       i32 = 0x0008; // select frequency-lock mode (rw)
pub const STA_INS:       i32 = 0x0010; // insert leap (rw)
pub const STA_DEL:       i32 = 0x0020; // delete leap (rw)
pub const STA_UNSYNC:    i32 = 0x0040; // clock unsynchronized (rw)
pub const STA_FREQHOLD:  i32 = 0x0080; // hold frequency (rw)
pub const STA_PPSSIGNAL: i32 = 0x0100; // PPS signal present (ro)
pub const STA_PPSJITTER: i32 = 0x0200; // PPS signal jitter exceeded (ro)
pub const STA_PPSWANDER: i32 = 0x0400; // PPS signal wander exceeded (ro)
pub const STA_PPSERROR:  i32 = 0x0800; // PPS signal calibration error (ro)
pub const STA_CLOCKERR:  i32 = 0x1000; // clock hardware fault (ro)
pub const STA_NANO:      i32 = 0x2000; // resolution (0 = us, 1 = ns) (ro)
pub const STA_MODE:      i32 = 0x4000; // mode (0 = PLL, 1 = FLL) (ro)
pub const STA_CLK:       i32 = 0x8000; // clock source (0 = A, 1 = B) (ro)

/// Clock states (time_state)
pub const TIME_OK:    i32 = 0; // clock synchronized, no leap second
pub const TIME_INS:   i32 = 1; // insert leap second
pub const TIME_DEL:   i32 = 2; // delete leap second
pub const TIME_OOP:   i32 = 3; // leap second in progress
pub const TIME_WAIT:  i32 = 4; // leap second has occurred
pub const TIME_ERROR: i32 = 5; // clock not synchronized
pub const TIME_BAD:   i32 = TIME_ERROR; // bw compat

/// Names of the interval timers, and structure defining a timer setting:
pub const ITIMER_REAL:    i32 = 0;
pub const ITIMER_VIRTUAL: i32 = 1;
pub const ITIMER_PROF:    i32 = 2;

/// The IDs of the various system clocks (for POSIX.1b interval timers):
pub const CLOCK_REALTIME:           i32 = 0;
pub const CLOCK_MONOTONIC:          i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID:  i32 = 3;
pub const CLOCK_MONOTONIC_RAW:      i32 = 4;
pub const CLOCK_REALTIME_COARSE:    i32 = 5;
pub const CLOCK_MONOTONIC_COARSE:   i32 = 6;
pub const CLOCK_BOOTTIME:           i32 = 7;
pub const CLOCK_REALTIME_ALARM:     i32 = 8;
pub const CLOCK_BOOTTIME_ALARM:     i32 = 9;
pub const CLOCK_SGI_CYCLE:          i32 = 10; // (do not use)
pub const CLOCK_TAI:                i32 = 11; // (do not use)
pub const CLOCKS_MASK:              i32 = (CLOCK_REALTIME | CLOCK_MONOTONIC);
pub const CLOCKS_MONO:              i32 = CLOCK_MONOTONIC;
pub const MAX_CLOCKS:               i32 = 16;

/// The various flags for setting POSIX.1b interval timers:
pub const TIMER_ABSTIME: i32 = 0x01;

/// For waitid
pub const WNOHANG:    i32 = 0x00000001;
pub const WUNTRACED:  i32 = 0x00000002;
pub const WSTOPPED:   i32 = WUNTRACED;
pub const WEXITED:    i32 = 0x00000004;
pub const WCONTINUED: i32 = 0x00000008;
pub const WNOWAIT:    i32 = 0x01000000; // Don't reap, just poll status.
pub const WNOTHREAD:  i32 = 0x20000000; // Don't wait on children of other threads in this group
pub const WALL:       i32 = 0x40000000; // Wait on all children, regardless of type
#[allow(overflowing_literals)]
pub const WCLONE:     i32 = 0x80000000; // Wait only on non-SIGCHLD children

/// First argument to waitid:
pub const P_AL:   i32 = 0;
pub const P_PID:  i32 = 1;
pub const P_PGID: i32 = 2;

/// eventfd.h
pub const EFD_SEMAPHORE:          i32 = (1 << 0);
pub const EFD_CLOEXEC:            i32 = O_CLOEXEC;
pub const EFD_NONBLOCK:           i32 = O_NONBLOCK;
pub const EFD_SHARED_FCNTL_FLAGS: i32 = (O_CLOEXEC | O_NONBLOCK);
pub const EFD_FLAGS_SET:          i32 = (EFD_SHARED_FCNTL_FLAGS | EFD_SEMAPHORE);

/// stat.h
/// Flags to be stx_mask
pub const STATX_TYPE:        u32 = 0x00000001; // Want/got stx_mode & S_IFMT
pub const STATX_MODE:        u32 = 0x00000002; // Want/got stx_mode & ~S_IFMT
pub const STATX_NLINK:       u32 = 0x00000004; // Want/got stx_nlink
pub const STATX_UID:         u32 = 0x00000008; // Want/got stx_uid
pub const STATX_GID:         u32 = 0x00000010; // Want/got stx_gid
pub const STATX_ATIME:       u32 = 0x00000020; // Want/got stx_atime
pub const STATX_MTIME:       u32 = 0x00000040; // Want/got stx_mtime
pub const STATX_CTIME:       u32 = 0x00000080; // Want/got stx_ctime
pub const STATX_INO:         u32 = 0x00000100; // Want/got stx_ino
pub const STATX_SIZE:        u32 = 0x00000200; // Want/got stx_size
pub const STATX_BLOCKS:      u32 = 0x00000400; // Want/got stx_blocks
pub const STATX_BASIC_STATS: u32 = 0x000007ff; // The stuff in the normal stat struct
pub const STATX_BTIME:       u32 = 0x00000800; // Want/got stx_btime
pub const STATX_ALL:         u32 = 0x00000fff; // All currently supported flags
pub const STATX__RESERVED:   u32 = 0x80000000; // Reserved for future struct statx expansion

/// Attributes to be found in stx_attributes and masked in stx_attributes_mask.
pub const STATX_ATTR_COMPRESSED: i32 = 0x00000004; // [I] File is compressed by the fs
pub const STATX_ATTR_IMMUTABLE:  i32 = 0x00000010; // [I] File is marked immutable
pub const STATX_ATTR_APPEND:     i32 = 0x00000020; // [I] File is append-only
pub const STATX_ATTR_NODUMP:     i32 = 0x00000040; // [I] File is not to be dumped
pub const STATX_ATTR_ENCRYPTED:  i32 = 0x00000800; // [I] File requires key to decrypt in fs
pub const STATX_ATTR_AUTOMOUNT:  i32 = 0x00001000; // Dir: Automount trigger

/// Flags for `getrandom`. (random.h)
pub const GRND_NONBLOCK: i32 = 0x0001; // Don't block and return EAGAIN instead
pub const GRND_RANDOM:   i32 = 0x0002; // Use the /dev/random pool instead of /dev/urandom

/// Cloning flags. (sched.h)
pub const CSIGNAL:              i32 = 0x000000ff; // signal mask to be sent at exit
pub const CLONE_VM:             i32 = 0x00000100; // set if VM shared between processes
pub const CLONE_FS:             i32 = 0x00000200; // set if fs info shared between processes
pub const CLONE_FILES:          i32 = 0x00000400; // set if open files shared between processes
pub const CLONE_SIGHAND:        i32 = 0x00000800; // set if signal handlers and blocked signals shared
pub const CLONE_PTRACE:         i32 = 0x00002000; // set if we want to let tracing continue on the child too
pub const CLONE_VFORK:          i32 = 0x00004000; // set if the parent wants the child to wake it up on mm_release
pub const CLONE_PARENT:         i32 = 0x00008000; // set if we want to have the same parent as the cloner
pub const CLONE_THREAD:         i32 = 0x00010000; // Same thread group?
pub const CLONE_NEWNS:          i32 = 0x00020000; // New mount namespace group
pub const CLONE_SYSVSEM:        i32 = 0x00040000; // share system V SEM_UNDO semantics
pub const CLONE_SETTLS:         i32 = 0x00080000; // create a new TLS for the child
pub const CLONE_PARENT_SETTID:  i32 = 0x00100000; // set the TID in the parent
pub const CLONE_CHILD_CLEARTID: i32 = 0x00200000; // clear the TID in the child
pub const CLONE_DETACHED:       i32 = 0x00400000; // Unused, ignored
pub const CLONE_UNTRACED:       i32 = 0x00800000; // set if the tracing process can't force CLONE_PTRACE on this clone
pub const CLONE_CHILD_SETTID:   i32 = 0x01000000; // set the TID in the child
pub const CLONE_NEWCGROUP:      i32 = 0x02000000; // New cgroup namespace
pub const CLONE_NEWUTS:         i32 = 0x04000000; // New utsname namespace
pub const CLONE_NEWIPC:         i32 = 0x08000000; // New ipc namespace
pub const CLONE_NEWUSER:        i32 = 0x10000000; // New user namespace
pub const CLONE_NEWPID:         i32 = 0x20000000; // New pid namespace
pub const CLONE_NEWNET:         i32 = 0x40000000; // New network namespace
#[allow(overflowing_literals)]
pub const CLONE_IO:             i32 = 0x80000000; // Clone io context

/// Scheduling policies
pub const SCHED_NORMAL:   i32 = 0;
pub const SCHED_FIFO:     i32 = 1;
pub const SCHED_RR:       i32 = 2;
pub const SCHED_BATCH:    i32 = 3;
/* SCHED_ISO: reserved but not implemented yet */
pub const SCHED_IDLE:     i32 = 5;
pub const SCHED_DEADLINE: i32 = 6;

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
pub const SCHED_RESET_ON_FORK: i32 = 0x40000000;

/// For the sched_{set,get}attr() calls
pub const SCHED_FLAG_RESET_ON_FORK: i32 = 0x01;
pub const SCHED_FLAG_RECLAIM:       i32 = 0x02;
pub const SCHED_FLAG_DL_OVERRUN:    i32 = 0x04;
pub const SCHED_FLAG_ALL: i32 = (SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN);

pub const SCHED_ATTR_SIZE_VER0: i32 = 48; // sizeof first published struct


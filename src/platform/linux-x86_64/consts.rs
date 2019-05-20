
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
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;


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


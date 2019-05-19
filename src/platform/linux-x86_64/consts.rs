
use super::types::{mode_t, key_t};

/// open() mode
pub const S_IRUSR: mode_t = 0400;
pub const S_IWUSR: mode_t = 0200;
pub const S_IXUSR: mode_t = 0100;
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
pub const O_RDONLY: i32 = 00;
pub const O_WRONLY: i32 = 01;
pub const O_RDWR: i32 = 02;
pub const O_CREAT: i32 = 0100;
pub const O_EXCL: i32 = 0200;
pub const O_NOCTTY: i32 = 0400;
pub const O_TRUNC: i32 = 01000;
pub const O_APPEND: i32 = 02000;
pub const O_NONBLOCK: i32 = 04000;
pub const O_SYNC: i32 = 04010000;
pub const O_ASYNC: i32 = 020000;

/// access() mode
pub const R_OK: i32 = 4;
pub const W_OK: i32 = 2;
pub const X_OK: i32 = 1;
pub const F_OK: i32 = 0;

/// sync_file_range() mode
pub const SYNC_FILE_RANGE_WAIT_BEFORE: i32 = 1;
pub const SYNC_FILE_RANGE_WRITE: i32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: i32 = 4;

pub const SPLICE_F_MOVE: i32 = 1;
pub const SPLICE_F_NONBLOCK: i32 = 2;
pub const SPLICE_F_MORE: i32 = 4;
pub const SPLICE_F_GIFT: i32 = 8;

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// Signals
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGIOT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;
pub const SIGIO: i32 = 29;
pub const SIGPOLL: i32 = 29;
pub const SIGPWR: i32 = 30;
pub const SIGSYS: i32 = 31;
pub const SIGUNUSED: i32 = 31;

pub const SIG_RT_MIN: i32 = 32;
pub const SIG_RTMAX: i32 = 64;

/// sigaction() sa_flags
pub const SA_NOCLDSTOP: i32 = 1;
pub const SA_NOCLDWAIT: i32 = 2;
pub const SA_SIGINFO: i32 = 4;
pub const SA_ONSTACK: i32 = 0x08000000;
pub const SA_RESTART: i32 = 0x10000000;
pub const SA_INTERRUPT: i32 = 0x20000000;
pub const SA_NODEFER: i32 = 0x40000000;
#[allow(overflowing_literals)]
pub const SA_RESETHAND: i32 = 0x80000000;

/// lseek() whence
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;


/// Poll event
pub const POLLIN: i32 = 0x001;
pub const POLLPRI: i32 = 0x002;
pub const POLLOUT: i32 = 0x004;
pub const POLLERR: i32 = 0x008;
pub const POLLHUP: i32 = 0x010;
pub const POLLNVAL: i32 = 0x020;
pub const POLLRDNORM: i32 = 0x040;
pub const POLLRDBAND: i32 = 0x080;
pub const POLLWRNORM: i32 = 0x100;
pub const POLLWRBAND: i32 = 0x200;

/// Mmap protection types
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;
pub const PROT_NONE: i32 = 0x0;
pub const PROT_GROWSDOWN: i32 = 0x01000000;
pub const PROT_GROWSUP: i32 = 0x02000000;

/// Mmap flags
pub const MAP_UNINITIALIZED: i32 = 0x00;
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_SHARED_VALIDATE: i32 = 0x03;
pub const MAP_TYPE: i32 = 0x0f;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_GROWSDOWN: i32 = 0x0100;
pub const MAP_DENYWRITE: i32 = 0x0800;
pub const MAP_EXECUTABLE: i32 = 0x1000;
pub const MAP_LOCKED: i32 = 0x2000;
pub const MAP_NORESERVE: i32 = 0x4000;
pub const MAP_POPULATE: i32 = 0x8000;
pub const MAP_NONBLOCK: i32 = 0x10000;
pub const MAP_STACK: i32 = 0x20000;
pub const MAP_HUGETLB: i32 = 0x40000;
pub const MAP_SYNC: i32 = 0x80000;
pub const MAP_FIXED_NOREPLACE: i32 = 0x100000;

pub const MAP_FAILED: i32 = -1;

/// Mmap lock
pub const MCL_CURRENT: i32 = 1;
pub const MCL_FUTURE: i32 = 2;
pub const MCL_ONFAULT: i32 = 4;

/// msync flags
pub const MS_ASYNC: i32 = 1;
pub const MS_SYNC: i32 = 4;
pub const MS_INVALIDATE: i32 = 2;

/// Mode bits for `msgget', `semget', and `shmget'.
pub const IPC_CREAT: i32 = 01000;
pub const IPC_EXCL: i32 = 02000;
pub const IPC_NOWAIT: i32 = 04000;

/// Control commands for `msgctl', `semctl', and `shmctl'. 
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

pub const IPC_PRIVATE: key_t = 0;


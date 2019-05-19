
use super::types::mode_t;

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

pub const SA_NOCLDSTOP: i32 = 1;
pub const SA_NOCLDWAIT: i32 = 2;
pub const SA_SIGINFO: i32 = 4;
pub const SA_ONSTACK: i32 = 0x08000000;
pub const SA_RESTART: i32 = 0x10000000;
pub const SA_INTERRUPT: i32 = 0x20000000;
pub const SA_NODEFER: i32 = 0x40000000;
#[allow(overflowing_literals)]
pub const SA_RESETHAND: i32 = 0x80000000;

/// Whence:
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

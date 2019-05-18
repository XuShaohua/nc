
use super::types::mode_t;

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

pub const O_RDONLY: isize = 00;
pub const O_WRONLY: isize = 01;
pub const O_RDWR: isize = 02;
pub const O_CREAT: isize = 0100;
pub const O_EXCL: isize = 0200;
pub const O_NOCTTY: isize = 0400;
pub const O_TRUNC: isize = 01000;
pub const O_APPEND: isize = 02000;
pub const O_NONBLOCK: isize = 04000;
pub const O_SYNC: isize = 04010000;
pub const O_ASYNC: isize = 020000;

pub const SYNC_FILE_RANGE_WAIT_BEFORE: isize = 1;
pub const SYNC_FILE_RANGE_WRITE: isize = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: isize = 4;

pub const SPLICE_F_MOVE: isize = 1;
pub const SPLICE_F_NONBLOCK: isize = 2;
pub const SPLICE_F_MORE: isize = 4;
pub const SPLICE_F_GIFT: isize = 8;

pub const SIG_BLOCK: isize = 0;
pub const SIG_UNBLOCK: isize = 1;
pub const SIG_SETMASK: isize = 2;

pub const SIGHUP: isize = 1;
pub const SIGINT: isize = 2;
pub const SIGQUIT: isize = 3;
pub const SIGILL: isize = 4;
pub const SIGTRAP: isize = 5;
pub const SIGABRT: isize = 6;
pub const SIGIOT: isize = 6;
pub const SIGBUS: isize = 7;
pub const SIGFPE: isize = 8;
pub const SIGKILL: isize = 9;
pub const SIGUSR1: isize = 10;
pub const SIGSEGV: isize = 11;
pub const SIGUSR2: isize = 12;
pub const SIGPIPE: isize = 13;
pub const SIGALRM: isize = 14;
pub const SIGTERM: isize = 15;
pub const SIGSTKFLT: isize = 16;
pub const SIGCHLD: isize = 17;
pub const SIGCONT: isize = 18;
pub const SIGSTOP: isize = 19;
pub const SIGTSTP: isize = 20;
pub const SIGTTIN: isize = 21;
pub const SIGTTOU: isize = 22;
pub const SIGURG: isize = 23;
pub const SIGXCPU: isize = 24;
pub const SIGXFSZ: isize = 25;
pub const SIGVTALRM: isize = 26;
pub const SIGPROF: isize = 27;
pub const SIGWINCH: isize = 28;
pub const SIGIO: isize = 29;
pub const SIGPOLL: isize = 29;
pub const SIGPWR: isize = 30;
pub const SIGSYS: isize = 31;
pub const SIGUNUSED: isize = 31;

pub const SIG_RT_MIN: isize = 32;
pub const SIG_RTMAX: isize = 64;

pub const SA_NOCLDSTOP: isize = 1;
pub const SA_NOCLDWAIT: isize = 2;
pub const SA_SIGINFO: isize = 4;
pub const SA_ONSTACK: isize = 0x08000000;
pub const SA_RESTART: isize = 0x10000000;
pub const SA_NODEFER: isize = 0x40000000;
pub const SA_RESETHAND: isize = 0x80000000;
pub const SA_INTERRUPT: isize = 0x20000000;


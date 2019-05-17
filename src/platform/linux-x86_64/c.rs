
use super::nums::*;
use super::types::*;
use super::syscall0;

pub fn fork() -> pid_t {
    unsafe {
        return syscall0(SYS_FORK) as pid_t;
    }
}

pub fn getpid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPID) as pid_t;
    }
}

pub fn getppid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPPID) as pid_t;
    }
}


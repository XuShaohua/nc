
use super::nums::*;
use super::syscall0;

pub fn getpid() -> isize {
    unsafe {
        return syscall0(SYS_GETPID) as isize;
    }
}

pub fn getppid() -> isize {
    unsafe {
        return syscall0(SYS_GETPPID) as isize;
    }
}

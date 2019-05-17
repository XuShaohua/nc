
use super::nums::*;
use super::types::*;
use super::{syscall0, syscall1, syscall3};

pub fn exit(status: u8) {
    unsafe {
        syscall1(SYS_EXIT, status as usize);
    }
}

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

pub fn write(fd: c_int, buf: &[u8]) -> ssize_t {
    unsafe {
        let ret = syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len());
        if (ret as isize) < 0 && (ret as isize) >= -256 {
            let errno = -(ret as isize) as c_int;
            panic!("errno: {}, ret: {}", errno, ret);
        }
        panic!("ret: {}", ret);
        return ret as ssize_t;
    }
}

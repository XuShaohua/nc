
use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::{syscall0, syscall1, syscall3};

//#[inline(always)]
//fn e(n: usize) -> usize {
//}

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

pub fn write(fd: c_int, buf: &[u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let ret = syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len());
        if (ret as isize) < 0 && (ret as isize) >= -256 {
            let errno = -(ret as isize) as i32;
            return Err(errno);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

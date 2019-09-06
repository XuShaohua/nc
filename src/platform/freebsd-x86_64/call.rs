use super::errno::*;
use super::sysno::*;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use crate::c_str::CString;
use alloc::vec::Vec;

pub fn exit(rval: i32) {
    unsafe {
        let rval = rval as usize;
        let _ret = syscall1(SYS_EXIT, rval);
    }
}

pub fn fork() -> Result<pid_t, Errno> {
    unsafe { syscall0(SYS_FORK).map(|ret| ret as pid_t) }
}

pub fn read(fd: i32, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let len = buf.len() as usize;
        syscall3(SYS_READ, fd, buf_ptr, len).map(|ret| ret as ssize_t)
    }
}

pub fn write(fd: i32, buf: &[u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        syscall3(SYS_WRITE, fd, buf_ptr, len).map(|ret| ret as ssize_t)
    }
}

pub fn open(path: &str, flags: i32, mode: i32) -> Result<i32, Errno> {
    unsafe {
        let path = CString::new(path);
        let path_ptr = path.as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        syscall3(SYS_OPEN, path_ptr, flags, mode).map(|ret| ret as i32)
    }
}

pub fn close(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        syscall1(SYS_CLOSE, fd).map(|_ret| ())
    }
}

pub fn wait4(pid: i32, status: &mut i32, options: i32) -> Result<i32, Errno> {
    unsafe {
        let pid = pid as usize;
        let status = status as *mut i32 as usize;
        let options = options as usize;
        syscall3(SYS_WAIT4, pid, status, options).map(|ret| ret as i32)
    }
}

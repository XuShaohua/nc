// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate alloc;

use crate::c_str::CString;
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

/// Terminate current process.
///
/// ```
/// nc::exit(0);
/// ```
pub fn exit(status: i32) {
    let status = status as usize;
    let _ret = syscall1(SYS_EXIT, status);
    unreachable!();
}

/// Read from a file descriptor.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [0_u8; 4 * 1024];
/// let ret = nc::read(fd, buf.as_mut_ptr() as usize, buf.len());
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap();
/// assert!(n_read <= buf.len() as nc::ssize_t);
/// assert!(nc::close(fd).is_ok());
/// ```
pub fn read(fd: i32, buf: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_READ, fd, buf, count).map(|ret| ret as ssize_t)
}

/// Write to a file descriptor.
///
/// ```
/// let path = "/tmp/nc-write";
/// let ret = nc::open(path, nc::O_CREAT | nc::O_WRONLY, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let msg = "Hello, Rust!";
/// let ret = nc::write(fd, msg.as_ptr() as usize, msg.len());
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub fn write(fd: i32, buf: &[u8]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let len = buf.len() as usize;
    syscall3(SYS_WRITE, fd, buf_ptr, len).map(|ret| ret as ssize_t)
}

/// Open and possibly create a file.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// ```
pub fn open<P: AsRef<Path>>(path: P, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    syscall3(SYS_OPEN, path_ptr, flags, mode).map(|ret| ret as i32)
}

/// Close a file descriptor.
///
/// ```
/// assert!(nc::close(2).is_ok());
/// ```
pub fn close(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_CLOSE, fd).map(drop)
}

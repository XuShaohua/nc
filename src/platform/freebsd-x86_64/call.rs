// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate alloc;

use crate::c_str::{strlen, CString};
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

/// Change working directory.
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let ret = nc::chdir(path);
/// assert!(ret.is_ok());
///
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = nc::getcwd(buf.as_mut_ptr() as usize, buf.len());
/// assert!(ret.is_ok());
/// // Remove null-terminal char.
/// let path_len = ret.unwrap() as usize - 1;
/// let new_cwd = std::str::from_utf8(&buf[..path_len]);
/// assert_eq!(new_cwd, Ok(path));
/// ```
pub fn chdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_CHDIR, filename_ptr).map(drop)
}

/// Change permissions of a file.
///
/// ```
/// let filename = "/tmp/nc-chmod";
/// let ret = nc::open(filename, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::chmod(filename, 0o600).is_ok());
/// assert!(nc::unlink(filename).is_ok());
/// ```
pub fn chmod<P: AsRef<Path>>(filename: P, mode: mode_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_CHMOD, filename_ptr, mode).map(drop)
}

/// Change ownership of a file.
///
/// ```
/// let filename = "/tmp/nc-chown";
/// let ret = nc::open(filename, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let ret = nc::chown(filename, 0, 0);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// assert!(nc::unlink(filename).is_ok());
/// ```
pub fn chown<P: AsRef<Path>>(filename: P, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_CHOWN, filename_ptr, user, group).map(drop)
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
pub fn exit(status: i32) {
    let status = status as usize;
    let _ret = syscall1(SYS_EXIT, status);
    unreachable!();
}

/// Change working directory.
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let fd = nc::open(path, nc::O_PATH, 0);
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = nc::fchdir(fd);
/// assert!(ret.is_ok());
/// assert!(nc::close(fd).is_ok());
/// ```
pub fn fchdir(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FCHDIR, fd).map(drop)
}

/// Create a child process.
///
/// ```
/// let pid = nc::fork();
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// ```
pub fn fork() -> Result<pid_t, Errno> {
    syscall0(SYS_FORK).map(|ret| ret as pid_t)
}

/// Get current working directory.
///
/// Note that `buf` shall be zeroized first.
///
/// ```
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = nc::getcwd(buf.as_mut_ptr() as usize, buf.len());
/// assert!(ret.is_ok());
/// // Remove null-terminal char.
/// let path_len = ret.unwrap() as usize - 1;
/// let cwd = std::str::from_utf8(&buf[..path_len]);
/// assert!(cwd.is_ok());
/// println!("cwd: {:?}", cwd);
/// ```
///
/// Wrapper of [__getcwd()].
pub fn getcwd(buf: usize, size: size_t) -> Result<ssize_t, Errno> {
    __getcwd(buf, size)?;
    Ok(strlen(buf, size) as ssize_t + 1)
}

/// Make a new name for a file.
///
/// ```
/// let old_filename = "/tmp/nc-link-src";
/// let ret = nc::open(old_filename, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let new_filename = "/tmp/nc-link-dst";
/// assert!(nc::link(old_filename, new_filename).is_ok());
/// assert!(nc::unlink(old_filename).is_ok());
/// assert!(nc::unlink(new_filename).is_ok());
/// ```
pub fn link<P: AsRef<Path>>(old_filename: P, new_filename: P) -> Result<(), Errno> {
    let old_filename = CString::new(old_filename.as_ref());
    let old_filename_ptr = old_filename.as_ptr() as usize;
    let new_filename = CString::new(new_filename.as_ref());
    let new_filename_ptr = new_filename.as_ptr() as usize;
    syscall2(SYS_LINK, old_filename_ptr, new_filename_ptr).map(drop)
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

/// Delete a name and possibly the file it refers to.
///
/// ```
/// let path = "/tmp/nc-unlink";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub fn unlink<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_UNLINK, filename_ptr).map(drop)
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
pub fn write(fd: i32, buf_ptr: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_WRITE, fd, buf_ptr, count).map(|ret| ret as ssize_t)
}

/// Get current working directory.
pub fn __getcwd(buf: usize, size: size_t) -> Result<(), Errno> {
    syscall2(SYS___GETCWD, buf, size).map(drop)
}

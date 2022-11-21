// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::wildcard_imports)]

extern crate alloc;

use crate::c_str::CString;
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

/// Accept a connection on a socket.
pub unsafe fn accept(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_in_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Accept a connection on a socket.
pub unsafe fn accept4(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
    flags: i32,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_in_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    let flags = flags as usize;
    syscall4(SYS_ACCEPT4, sockfd, addr_ptr, addrlen_ptr, flags).map(drop)
}

/// Check user's permission for a file.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::access("/etc/passwd", nc::F_OK) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::access("/etc/passwd", nc::X_OK) };
/// assert!(ret.is_err());
/// ```
pub unsafe fn access<P: AsRef<Path>>(filename: P, mode: i32) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_ACCESS, filename_ptr, mode).map(drop)
}

/// Switch process accounting.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-acct";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::acct(path) };
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn acct<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_ACCT, filename_ptr).map(drop)
}

/// Bind a name to a socket.
pub unsafe fn bind(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *const sockaddr_in_t as usize;
    let addrlen = addrlen as usize;
    syscall3(SYS_BIND, sockfd, addr_ptr, addrlen).map(drop)
}

/// Change working directory.
///
/// # Example
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let ret = unsafe { nc::chdir(path) };
/// assert!(ret.is_ok());
///
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = unsafe { nc::getcwd(buf.as_mut_ptr() as usize, buf.len()) };
/// assert!(ret.is_ok());
/// // Remove null-terminal char.
/// let path_len = ret.unwrap() as usize - 1;
/// let new_cwd = std::str::from_utf8(&buf[..path_len]);
/// assert_eq!(new_cwd, Ok(path));
/// ```
pub unsafe fn chdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_CHDIR, filename_ptr).map(drop)
}

/// Change permissions of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-chmod";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644,
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::chmod(filename, 0o600) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn chmod<P: AsRef<Path>>(filename: P, mode: mode_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_CHMOD, filename_ptr, mode).map(drop)
}

/// Change ownership of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-chown";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, filename, nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::chown(filename, 0, 0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn chown<P: AsRef<Path>>(filename: P, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_CHOWN, filename_ptr, user, group).map(drop)
}

/// Change the root directory.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::chroot("/") };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn chroot<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_CHROOT, filename_ptr).map(drop)
}

/// Get resolution(precision) of the specific clock.
///
/// # Example
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = unsafe { nc::clock_getres(nc::CLOCK_BOOTTIME, &mut tp) };
/// assert!(ret.is_ok());
/// assert!(tp.tv_nsec > 0);
/// ```
pub unsafe fn clock_getres(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *mut timespec_t as usize;
    syscall2(SYS_CLOCK_GETRES, which_clock, tp_ptr).map(drop)
}

/// Get time of specific clock.
///
/// # Example
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = unsafe { nc::clock_gettime(nc::CLOCK_REALTIME_COARSE, &mut tp) };
/// assert!(ret.is_ok());
/// assert!(tp.tv_sec > 0);
/// ```
pub unsafe fn clock_gettime(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *mut timespec_t as usize;
    syscall2(SYS_CLOCK_GETTIME, which_clock, tp_ptr).map(drop)
}

/// High resolution sleep with a specific clock.
///
/// # Example
///
/// ```
/// let t = nc::timespec_t {
///     tv_sec: 1,
///     tv_nsec: 0,
/// };
/// let mut rem = nc::timespec_t::default();
/// let ret = unsafe { nc::clock_nanosleep(nc::CLOCK_MONOTONIC, 0, &t, &mut rem) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn clock_nanosleep(
    which_clock: clockid_t,
    flags: i32,
    rqtp: &timespec_t,
    rmtp: &mut timespec_t,
) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let flags = flags as usize;
    let rqtp_ptr = rqtp as *const timespec_t as usize;
    let rmtp_ptr = rmtp as *mut timespec_t as usize;
    syscall4(SYS_CLOCK_NANOSLEEP, which_clock, flags, rqtp_ptr, rmtp_ptr).map(drop)
}

/// Set time of specific clock.
///
/// # Example
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = unsafe { nc::clock_gettime(nc::CLOCK_REALTIME, &mut tp) };
/// assert!(ret.is_ok());
/// assert!(tp.tv_sec > 0);
/// let ret = unsafe { nc::clock_settime(nc::CLOCK_REALTIME, &tp) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn clock_settime(which_clock: clockid_t, tp: &timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *const timespec_t as usize;
    syscall2(SYS_CLOCK_SETTIME, which_clock, tp_ptr).map(drop)
}

/// Close a file descriptor.
///
/// # Example
///
/// ```
/// const STDERR_FD: i32 = 2;
/// let ret = unsafe { nc::close(STDERR_FD) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn close(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_CLOSE, fd).map(drop)
}

/// Initialize a connection on a socket.
pub unsafe fn connect(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    // TODO(Shaohua): Use sockaddr_t generic type.
    let addr_ptr = addr as *const sockaddr_in_t as usize;
    let addrlen = addrlen as usize;
    syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen).map(drop)
}

/// Copy a range of data from one file to another.
///
/// # Example
///
/// ```
/// let path_in = "/etc/passwd";
/// let fd_in = unsafe { nc::openat(nc::AT_FDCWD, path_in, nc::O_RDONLY, 0) };
/// assert!(fd_in.is_ok());
/// let fd_in = fd_in.unwrap();
/// let path_out = "/tmp/nc-copy-file-range";
/// let fd_out = unsafe { nc::openat(nc::AT_FDCWD, path_out, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd_out.is_ok());
/// let fd_out = fd_out.unwrap();
/// let mut off_in = 0;
/// let mut off_out = 0;
/// let copy_len = 64;
/// let ret = unsafe { nc::copy_file_range(fd_in, &mut off_in, fd_out, &mut off_out, copy_len, 0) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(copy_len as nc::ssize_t));
/// let ret = unsafe { nc::close(fd_in) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd_out) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path_out, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn copy_file_range(
    fd_in: i32,
    off_in: &mut loff_t,
    fd_out: i32,
    off_out: &mut loff_t,
    len: size_t,
    flags: u32,
) -> Result<ssize_t, Errno> {
    let fd_in = fd_in as usize;
    let off_in_ptr = off_in as *mut loff_t as usize;
    let fd_out = fd_out as usize;
    let off_out_ptr = off_out as *mut loff_t as usize;
    let flags = flags as usize;
    syscall6(
        SYS_COPY_FILE_RANGE,
        fd_in,
        off_in_ptr,
        fd_out,
        off_out_ptr,
        len,
        flags,
    )
    .map(|ret| ret as ssize_t)
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-dup-file";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let fd_dup = unsafe { nc::dup(fd) };
/// assert!(fd_dup.is_ok());
/// let fd_dup = fd_dup.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd_dup) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn dup(oldfd: i32) -> Result<i32, Errno> {
    let oldfd = oldfd as usize;
    syscall1(SYS_DUP, oldfd).map(|ret| ret as i32)
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-dup2-file";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let newfd = 8;
/// let ret = unsafe { nc::dup2(fd, newfd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(newfd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn dup2(oldfd: i32, newfd: i32) -> Result<(), Errno> {
    let oldfd = oldfd as usize;
    let newfd = newfd as usize;
    syscall2(SYS_DUP2, oldfd, newfd).map(drop)
}

/// Execute a new program.
///
/// TODO(Shaohua): type of argv and env will be changed.
/// And return value might be changed too.
///
/// # Example
///
/// ```
/// let args = [""];
/// let env = [""];
/// let ret = unsafe { nc::execve("/bin/ls", &args, &env) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn execve<P: AsRef<Path>>(
    filename: P,
    argv: &[&str],
    env: &[&str],
) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let argv_ptr = argv.as_ptr() as usize;
    let env_ptr = env.as_ptr() as usize;
    syscall3(SYS_EXECVE, filename_ptr, argv_ptr, env_ptr).map(drop)
}

/// Terminate current process.
///
/// # Example
///
/// ```
/// unsafe { nc::exit(0); }
/// ```
pub unsafe fn exit(status: i32) -> ! {
    let status = status as usize;
    let _ret = syscall1(SYS_EXIT, status);
    unreachable!();
}

/// Check user's permission for a file.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::faccessat(nc::AT_FDCWD, "/etc/passwd", nc::F_OK) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn faccessat<P: AsRef<Path>>(dfd: i32, filename: P, mode: i32) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall3(SYS_FACCESSAT, dfd, filename_ptr, mode).map(drop)
}

/// Change working directory.
///
/// # Example
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_PATH, 0) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::fchdir(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchdir(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FCHDIR, fd).map(drop)
}

/// Change permissions of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-fchmod";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::fchmod(fd, 0o600) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchmod(fd: i32, mode: mode_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let mode = mode as usize;
    syscall2(SYS_FCHMOD, fd, mode).map(drop)
}

/// Change permissions of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-fchmodat";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::fchmodat(nc::AT_FDCWD, filename, 0o600) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchmodat<P: AsRef<Path>>(dirfd: i32, filename: P, mode: mode_t) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall3(SYS_FCHMODAT, dirfd, filename_ptr, mode).map(drop)
}

/// Change ownership of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-fchown";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::fchown(fd, 0, 0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchown(fd: i32, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_FCHOWN, fd, user, group).map(drop)
}

/// Change ownership of a file.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-fchown";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::fchownat(nc::AT_FDCWD, filename, 0, 0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename,0 ) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchownat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    user: uid_t,
    group: gid_t,
    flag: i32,
) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    let flag = flag as usize;
    syscall5(SYS_FCHOWNAT, dirfd, filename_ptr, user, group, flag).map(drop)
}

/// manipulate file descriptor.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let ret = unsafe { nc::fcntl(fd, nc::F_DUPFD, 0) };
/// assert!(ret.is_ok());
/// let fd2 = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd2) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    syscall3(SYS_FCNTL, fd, cmd, arg).map(|ret| ret as i32)
}

/// Flush all modified in-core data (exclude metadata) refered by `fd` to disk.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-fdatasync";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let msg = b"Hello, Rust";
/// let ret = unsafe { nc::write(fd, msg.as_ptr() as usize, msg.len()) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fdatasync(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FDATASYNC, fd).map(drop)
}

/// Apply or remove an advisory lock on an open file.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-flock";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::flock(fd, nc::LOCK_EX) };
/// assert!(ret.is_ok());
/// let msg = "Hello, Rust";
/// let ret = unsafe { nc::write(fd, msg.as_ptr() as usize, msg.len()) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::flock(fd, nc::LOCK_UN) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path,0 ) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn flock(fd: i32, operation: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    let operation = operation as usize;
    syscall2(SYS_FLOCK, fd, operation).map(drop)
}

/// Create a child process.
///
/// # Example
///
/// ```
/// let pid = unsafe { nc::fork() };
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// ```
pub unsafe fn fork() -> Result<pid_t, Errno> {
    syscall0(SYS_FORK).map(|ret| ret as pid_t)
}

/// Get file status about a file descriptor.
///
/// # example
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_PATH, 0) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut stat = nc::stat_t::default();
/// let ret = unsafe { nc::fstat(fd, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a directory.
/// assert_eq!((stat.st_mode & nc::S_IFMT), nc::S_IFDIR);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fstat(fd: i32, statbuf: &mut stat_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let statbuf_ptr = statbuf as *mut stat_t as usize;
    syscall2(SYS_FSTAT, fd, statbuf_ptr).map(drop)
}

/// Get file status.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat_t::default();
/// let ret = unsafe { nc::fstatat(nc::AT_FDCWD, path, &mut stat, nc::AT_SYMLINK_NOFOLLOW) };
/// assert!(ret.is_ok());
/// assert_eq!((stat.st_mode & nc::S_IFMT), nc::S_IFREG);
/// ```
pub unsafe fn fstatat<P: AsRef<Path>>(
    dfd: i32,
    filename: P,
    statbuf: &mut stat_t,
    flag: i32,
) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = statbuf as *mut stat_t as usize;
    let flag = flag as usize;
    syscall4(SYS_FSTATAT, dfd, filename_ptr, statbuf_ptr, flag).map(drop)
}

/// Get filesystem statistics.
///
/// # Example
///
/// ```
/// let path = "/usr";
/// // Open folder directly.
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_PATH, 0) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut statfs = nc::statfs_t::default();
/// let ret = unsafe { nc::fstatfs(fd, &mut statfs) };
/// assert!(ret.is_ok());
/// assert!(statfs.f_bfree > 0);
/// assert!(statfs.f_bavail > 0);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fstatfs(fd: i32, buf: &mut statfs_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let buf_ptr = buf as *mut statfs_t as usize;
    syscall2(SYS_FSTATFS, fd, buf_ptr).map(drop)
}

/// Flush all modified in-core data refered by `fd` to disk.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-fsync";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let buf = b"Hello, Rust";
/// let n_write = unsafe { nc::write(fd, buf.as_ptr() as usize, buf.len()) };
/// assert_eq!(n_write, Ok(buf.len() as isize));
/// let ret = unsafe { nc::fsync(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fsync(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FSYNC, fd).map(drop)
}

/// Truncate an opened file to a specified length.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-ftruncate";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::ftruncate(fd, 64 * 1024) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn ftruncate(fd: i32, length: off_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let length = length as usize;
    syscall2(SYS_FTRUNCATE, fd, length).map(drop)
}

/// Change timestamp of a file relative to a directory file discriptor.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-futimesat";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let times = [
///     nc::timeval_t {
///         tv_sec: 100,
///         tv_usec: 0,
///     },
///     nc::timeval_t {
///         tv_sec: 10,
///         tv_usec: 0,
///     },
/// ];
/// let ret = unsafe { nc::futimesat(nc::AT_FDCWD, path, &times) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn futimesat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    times: &[timeval_t; 2],
) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let times_ptr = times.as_ptr() as usize;
    syscall3(SYS_FUTIMESAT, dirfd, filename_ptr, times_ptr).map(drop)
}

/// Get the effective group ID of the calling process.
///
/// # Example
///
/// ```
/// let egid = unsafe { nc::getegid() };
/// assert!(egid > 0);
/// ```
#[must_use]
pub unsafe fn getegid() -> gid_t {
    // This function is always successful.
    syscall0(SYS_GETEGID).expect("getegid() failed") as gid_t
}

/// Get the effective user ID of the calling process.
///
/// # Example
///
/// ```
/// let euid = unsafe { nc::geteuid() };
/// assert!(euid > 0);
/// ```
#[must_use]
pub unsafe fn geteuid() -> uid_t {
    // This function is always successful.
    syscall0(SYS_GETEUID).expect("geteuid() failed") as uid_t
}

/// Get the real group ID of the calling process.
///
/// # Example
///
/// ```
/// let gid = unsafe { nc::getgid() };
/// assert!(gid > 0);
/// ```
#[must_use]
pub unsafe fn getgid() -> gid_t {
    // This function is always successful.
    syscall0(SYS_GETGID).expect("getgid() failed") as gid_t
}

/// Get list of supplementary group Ids.
///
/// # Example
///
/// ```
/// let mut groups = vec![];
/// let ret = unsafe { nc::getgroups(0, &mut groups) };
/// assert!(ret.is_ok());
/// let total_num = ret.unwrap();
/// groups.resize(total_num as usize, 0);
///
/// let ret = unsafe { nc::getgroups(total_num, &mut groups) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(total_num));
/// ```
pub unsafe fn getgroups(size: i32, group_list: &mut [gid_t]) -> Result<i32, Errno> {
    let size = size as usize;
    let group_ptr = group_list.as_mut_ptr() as usize;
    syscall2(SYS_GETGROUPS, size, group_ptr).map(|ret| ret as i32)
}

/// Get value of an interval timer.
///
/// # Example
///
/// ```
/// use core::mem::size_of;
///
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
///     let msg = "Hello alarm";
///     let _ = unsafe { nc::write(2, msg.as_ptr() as usize, msg.len()) };
/// }
///
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     sa_flags: 0,
///     ..nc::sigaction_t::default()
/// };
/// let mut old_sa = nc::sigaction_t::default();
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>()) };
/// assert!(ret.is_ok());
///
/// // Single shot timer, actived after 1 second.
/// let itv = nc::itimerval_t {
///     it_value: nc::timeval_t {
///         tv_sec: 1,
///         tv_usec: 0,
///     },
///     it_interval: nc::timeval_t {
///         tv_sec: 0,
///         tv_usec: 0,
///     },
/// };
/// let mut prev_itv = nc::itimerval_t::default();
/// let ret = unsafe { nc::setitimer(nc::ITIMER_REAL, &itv, &mut prev_itv) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);
///
/// let mask = nc::sigset_t::default();
/// let _ret = unsafe { nc::rt_sigsuspend(&mask, size_of::<nc::sigset_t>()) };
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert_eq!(prev_itv.it_value.tv_sec, 0);
/// assert_eq!(prev_itv.it_value.tv_usec, 0);
/// ```
pub unsafe fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    let which = which as usize;
    let curr_val_ptr = curr_val as *mut itimerval_t as usize;
    syscall2(SYS_GETITIMER, which, curr_val_ptr).map(drop)
}

/// Get name of connected peer socket.
pub unsafe fn getpeername(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_in_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_GETPEERNAME, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Returns the PGID(process group ID) of the process specified by `pid`.
///
/// # Example
///
/// ```
/// let ppid = unsafe { nc::getppid() };
/// let pgid = unsafe { nc::getpgid(ppid) };
/// assert!(pgid.is_ok());
/// ```
pub unsafe fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    syscall1(SYS_GETPGID, pid).map(|ret| ret as pid_t)
}

/// Get the process group ID of the calling process.
///
/// # Example
///
/// ```
/// let pgroup = unsafe { nc::getpgrp() };
/// assert!(pgroup > 0);
/// ```
#[must_use]
pub unsafe fn getpgrp() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPGRP).expect("getpgrp() failed") as pid_t
}

/// Get the process ID (PID) of the calling process.
///
/// # Example
///
/// ```
/// let pid = unsafe { nc::getpid() };
/// assert!(pid > 0);
/// ```
#[must_use]
pub unsafe fn getpid() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPID).expect("getpid() failed") as pid_t
}

/// Get the process ID of the parent of the calling process.
///
/// # Example
///
/// ```
/// let ppid = unsafe { nc::getppid() };
/// assert!(ppid > 0);
/// ```
#[must_use]
pub unsafe fn getppid() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPPID).expect("getppid() failed") as pid_t
}

/// Get program scheduling priority.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::getpriority(nc::PRIO_PROCESS, nc::getpid()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn getpriority(which: i32, who: i32) -> Result<i32, Errno> {
    let which = which as usize;
    let who = who as usize;
    syscall2(SYS_GETPRIORITY, which, who).map(|ret| {
        let ret = ret as i32;
        if ret > PRIO_MAX {
            return PRIO_MAX - ret;
        }
        ret
    })
}

/// Obtain a series of random bytes.
///
/// # Example
///
/// ```
/// let mut buf = [0_u8; 32];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::getrandom(&mut buf, buf_len, 0) };
/// assert!(ret.is_ok());
/// let size = ret.unwrap() as usize;
/// assert!(size <= buf_len);
/// ```
pub unsafe fn getrandom(buf: &mut [u8], buf_len: usize, flags: u32) -> Result<ssize_t, Errno> {
    let buf_ptr = buf.as_mut_ptr() as usize;
    let flags = flags as usize;
    syscall3(SYS_GETRANDOM, buf_ptr, buf_len, flags).map(|ret| ret as ssize_t)
}

/// Get real, effect and saved group ID.
///
/// # Example
///
/// ```
/// let mut rgid = 0;
/// let mut egid = 0;
/// let mut sgid = 0;
/// let ret = unsafe { nc::getresgid(&mut rgid, &mut egid, &mut sgid) };
/// assert!(ret.is_ok());
/// assert!(rgid > 0);
/// assert!(egid > 0);
/// assert!(sgid > 0);
/// ```
pub unsafe fn getresgid(rgid: &mut gid_t, egid: &mut gid_t, sgid: &mut gid_t) -> Result<(), Errno> {
    let rgid_ptr = rgid as *mut gid_t as usize;
    let egid_ptr = egid as *mut gid_t as usize;
    let sgid_ptr = sgid as *mut gid_t as usize;
    syscall3(SYS_GETRESGID, rgid_ptr, egid_ptr, sgid_ptr).map(drop)
}

/// Get real, effect and saved user ID.
///
/// # Example
///
/// ```
/// let mut ruid = 0;
/// let mut euid = 0;
/// let mut suid = 0;
/// let ret = unsafe { nc::getresuid(&mut ruid, &mut euid, &mut suid) };
/// assert!(ret.is_ok());
/// assert!(ruid > 0);
/// assert!(euid > 0);
/// assert!(suid > 0);
/// ```
pub unsafe fn getresuid(ruid: &mut uid_t, euid: &mut uid_t, suid: &mut uid_t) -> Result<(), Errno> {
    let ruid_ptr = ruid as *mut uid_t as usize;
    let euid_ptr = euid as *mut uid_t as usize;
    let suid_ptr = suid as *mut uid_t as usize;
    syscall3(SYS_GETRESUID, ruid_ptr, euid_ptr, suid_ptr).map(drop)
}

/// Get resource limit.
///
/// # Example
///
/// ```
/// let mut rlimit = nc::rlimit_t::default();
/// let ret = unsafe { nc::getrlimit(nc::RLIMIT_NOFILE, &mut rlimit) };
/// assert!(ret.is_ok());
/// assert!(rlimit.rlim_cur > 0);
/// assert!(rlimit.rlim_max > 0);
/// ```
pub unsafe fn getrlimit(resource: i32, rlim: &mut rlimit_t) -> Result<(), Errno> {
    let resource = resource as usize;
    let rlim_ptr = rlim as *mut rlimit_t as usize;
    syscall2(SYS_GETRLIMIT, resource, rlim_ptr).map(drop)
}

/// Get resource usage.
///
/// # Example
///
/// ```
/// let mut usage = nc::rusage_t::default();
/// let ret = unsafe { nc::getrusage(nc::RUSAGE_SELF, &mut usage) };
/// assert!(ret.is_ok());
/// assert!(usage.ru_maxrss > 0);
/// assert_eq!(usage.ru_nswap, 0);
/// ```
pub unsafe fn getrusage(who: i32, usage: &mut rusage_t) -> Result<(), Errno> {
    let who = who as usize;
    let usage_ptr = usage as *mut rusage_t as usize;
    syscall2(SYS_GETRUSAGE, who, usage_ptr).map(drop)
}

/// Get session Id.
///
/// # Example
///
/// ```
/// let ppid = unsafe { nc::getppid() };
/// let sid = unsafe { nc::getsid(ppid) };
/// assert!(sid > 0);
/// ```
#[must_use]
pub unsafe fn getsid(pid: pid_t) -> pid_t {
    let pid = pid as usize;
    // This function is always successful.
    syscall1(SYS_GETSID, pid).expect("getsid() failed") as pid_t
}

/// Get current address to which the socket `sockfd` is bound.
pub unsafe fn getsockname(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_in_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_GETSOCKNAME, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Get options on sockets
pub unsafe fn getsockopt(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: &mut usize,
    optlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let optname = optname as usize;
    let optval_ptr = optval as *mut usize as usize;
    let optlen_ptr = optlen as *mut socklen_t as usize;
    syscall5(
        SYS_GETSOCKOPT,
        sockfd,
        level,
        optname,
        optval_ptr,
        optlen_ptr,
    )
    .map(drop)
}

/// Get time.
///
/// # Example
///
/// ```
/// let mut tv = nc::timeval_t::default();
/// let mut tz = nc::timezone_t::default();
/// let ret = unsafe { nc::gettimeofday(&mut tv, &mut tz) };
/// assert!(ret.is_ok());
/// assert!(tv.tv_sec > 1611380386);
/// ```
pub unsafe fn gettimeofday(timeval: &mut timeval_t, tz: &mut timezone_t) -> Result<(), Errno> {
    let timeval_ptr = timeval as *mut timeval_t as usize;
    let tz_ptr = tz as *mut timezone_t as usize;
    syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop)
}

/// Get the real user ID of the calling process.
///
/// # Example
///
/// ```
/// let uid = unsafe { nc::getuid() };
/// assert!(uid > 0);
/// ```
#[must_use]
pub unsafe fn getuid() -> uid_t {
    // This function is always successful.
    syscall0(SYS_GETUID).expect("getuid() failed") as uid_t
}

/// Control device.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-ioctl";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut attr: i32 = 0;
/// let cmd = -2146933247; // nc::FS_IOC_GETFLAGS
/// let ret = unsafe { nc::ioctl(fd, cmd, &mut attr as *mut i32 as usize) };
/// assert!(ret.is_ok());
/// println!("attr: {}", attr);
///
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn ioctl(fd: i32, cmd: i32, arg: usize) -> Result<(), Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    syscall3(SYS_IOCTL, fd, cmd, arg).map(drop)
}

/// Send signal to a process.
///
/// # Example
///
/// ```
/// let pid = unsafe { nc::fork() };
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// if pid == 0 {
///     // child process.
///     let args = [""];
///     let env = [""];
///     let ret = unsafe { nc::execve("/usr/bin/yes", &args, &env) };
///     assert!(ret.is_ok());
/// } else {
///     // parent process.
///     let ret = unsafe { nc::kill(pid, nc::SIGTERM) };
///     assert!(ret.is_ok());
/// }
/// ```
pub unsafe fn kill(pid: pid_t, signal: i32) -> Result<(), Errno> {
    let pid = pid as usize;
    let signal = signal as usize;
    syscall2(SYS_KILL, pid, signal).map(drop)
}

/// Change ownership of a file. Does not deference symbolic link.
///
/// # Example
///
/// ```
/// let filename = "/tmp/nc-lchown";
/// let ret = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::lchown(filename, 0, 0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn lchown<P: AsRef<Path>>(filename: P, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_LCHOWN, filename_ptr, user, group).map(drop)
}

/// Make a new name for a file.
///
/// # Example
///
/// ```
/// let old_filename = "/tmp/nc-link-src";
/// let ret = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         old_filename,
///         nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
///         0o644
///     )
/// };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let new_filename = "/tmp/nc-link-dst";
/// let ret = unsafe { nc::link(old_filename, new_filename) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, old_filename, 0) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, new_filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn link<P: AsRef<Path>>(old_filename: P, new_filename: P) -> Result<(), Errno> {
    let old_filename = CString::new(old_filename.as_ref());
    let old_filename_ptr = old_filename.as_ptr() as usize;
    let new_filename = CString::new(new_filename.as_ref());
    let new_filename_ptr = new_filename.as_ptr() as usize;
    syscall2(SYS_LINK, old_filename_ptr, new_filename_ptr).map(drop)
}

/// Make a new name for a file.
///
/// # Example
///
/// ```
/// let old_filename = "/tmp/nc-linkat-src";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, old_filename, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let new_filename = "/tmp/nc-linkat-dst";
/// let flags = nc::AT_SYMLINK_FOLLOW;
/// let ret = unsafe { nc::linkat(nc::AT_FDCWD, old_filename, nc::AT_FDCWD,  new_filename, flags) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, old_filename, 0) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, new_filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn linkat<P: AsRef<Path>>(
    olddfd: i32,
    oldfilename: P,
    newdfd: i32,
    newfilename: P,
    flags: i32,
) -> Result<(), Errno> {
    let olddfd = olddfd as usize;
    let oldfilename = CString::new(oldfilename.as_ref());
    let oldfilename_ptr = oldfilename.as_ptr() as usize;
    let newdfd = newdfd as usize;
    let newfilename = CString::new(newfilename.as_ref());
    let newfilename_ptr = newfilename.as_ptr() as usize;
    let flags = flags as usize;
    syscall5(
        SYS_LINKAT,
        olddfd,
        oldfilename_ptr,
        newdfd,
        newfilename_ptr,
        flags,
    )
    .map(drop)
}

/// Listen for connections on a socket.
pub unsafe fn listen(sockfd: i32, backlog: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let backlog = backlog as usize;
    syscall2(SYS_LISTEN, sockfd, backlog).map(drop)
}

/// Reposition file offset.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::lseek(fd, 42, nc::SEEK_SET) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn lseek(fd: i32, offset: off_t, whence: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    let offset = offset as usize;
    let whence = whence as usize;
    syscall3(SYS_LSEEK, fd, offset, whence).map(drop)
}

/// Give advice about use of memory.
///
/// # Example
///
/// ```
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let addr = unsafe {
///     nc::mmap(
///         0,
///         map_length,
///         nc::PROT_READ | nc::PROT_WRITE,
///         nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
///         -1,
///         0,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// // Set the third page readonly. And we will run into SIGSEGV when updating it.
/// let ret = unsafe { nc::madvise(addr + 2 * nc::PAGE_SIZE, nc::PAGE_SIZE, nc::MADV_RANDOM) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn madvise(addr: usize, len: size_t, advice: i32) -> Result<(), Errno> {
    let advice = advice as usize;
    syscall3(SYS_MADVISE, addr, len, advice).map(drop)
}

/// mincore() returns the memory residency status of the pages in the
/// current process's address space specified by [addr, addr + len).
/// The status is returned in a vector of bytes.  The least significant
/// bit of each byte is 1 if the referenced page is in memory, otherwise
/// it is zero.
///
/// Because the status of a page can change after mincore() checks it
/// but before it returns to the application, the returned vector may
/// contain stale information.  Only locked pages are guaranteed to
/// remain in memory.
///
/// return values:
///  zero    - success
///  -EFAULT - vec points to an illegal address
///  -EINVAL - addr is not a multiple of `PAGE_SIZE`
///  -ENOMEM - Addresses in the range [addr, addr + len] are
/// invalid for the address space of this process, or specify one or
/// more pages which are not currently mapped
///  -EAGAIN - A kernel resource was temporarily unavailable.
pub unsafe fn mincore(start: usize, len: size_t, vec: *const u8) -> Result<(), Errno> {
    let vec_ptr = vec as usize;
    syscall3(SYS_MINCORE, start, len, vec_ptr).map(drop)
}

/// Create a directory.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-mkdir";
/// let ret = unsafe { nc::mkdir(path, 0o755) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, nc::AT_REMOVEDIR) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mkdir<P: AsRef<Path>>(filename: P, mode: mode_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_MKDIR, filename_ptr, mode).map(drop)
}

/// Create a directory.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-mkdir";
/// let ret = unsafe { nc::mkdirat(nc::AT_FDCWD, path, 0o755) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, nc::AT_REMOVEDIR) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mkdirat<P: AsRef<Path>>(dirfd: i32, filename: P, mode: mode_t) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall3(SYS_MKDIRAT, dirfd, filename_ptr, mode).map(drop)
}

/// Create a special or ordinary file.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-mknodat";
/// // Create a named pipe.
/// let ret = unsafe { nc::mknodat(nc::AT_FDCWD, path, nc::S_IFIFO | nc::S_IRUSR | nc::S_IWUSR, 0) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mknodat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    mode: mode_t,
    dev: dev_t,
) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    let dev = dev as usize;
    syscall4(SYS_MKNODAT, dirfd, filename_ptr, mode, dev).map(drop)
}

/// Lock memory.
///
/// # Example
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let ret = unsafe { nc::mlock(passwd_buf.as_ptr() as usize, passwd_buf.len()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlock(addr: usize, len: size_t) -> Result<(), Errno> {
    syscall2(SYS_MLOCK, addr, len).map(drop)
}

/// Lock memory.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::mlockall(nc::MCL_CURRENT) };
/// // We got out-of-memory error in CI environment.
/// assert!(ret.is_ok() || ret == Err(nc::ENOMEM));
/// ```
pub unsafe fn mlockall(flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    syscall1(SYS_MLOCKALL, flags).map(drop)
}

/// Map files or devices into memory.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let mut sb = nc::stat_t::default();
/// let ret = unsafe { nc::fstat(fd, &mut sb) };
/// assert!(ret.is_ok());
///
/// let offset: usize = 0;
/// let length: usize = sb.st_size as usize - offset;
/// // Offset for mmap must be page aligned.
/// let pa_offset: usize = offset & !(nc::PAGE_SIZE - 1);
/// let map_length = length + offset - pa_offset;
///
/// let addr = unsafe {
///     nc::mmap(
///         0, // 0 as NULL
///         map_length,
///         nc::PROT_READ,
///         nc::MAP_PRIVATE,
///         fd,
///         pa_offset as nc::off_t,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// let n_write = unsafe { nc::write(1, addr + offset - pa_offset, length) };
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mmap(
    start: usize,
    len: size_t,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: off_t,
) -> Result<usize, Errno> {
    let prot = prot as usize;
    let flags = flags as usize;
    let fd = fd as usize;
    let offset = offset as usize;
    syscall6(SYS_MMAP, start, len, prot, flags, fd, offset)
}

/// Mount filesystem.
///
/// # Example
///
/// ```
/// let target_dir = "/tmp/nc-mount";
/// let ret = unsafe { nc::mkdirat(nc::AT_FDCWD, target_dir, 0o755) };
/// assert!(ret.is_ok());
///
/// let src_dir = "/etc";
/// let fs_type = "";
/// let mount_flags = nc::MS_BIND | nc::MS_RDONLY;
/// let data = 0;
/// let ret = unsafe { nc::mount(src_dir, target_dir, fs_type, mount_flags, data) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
///
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, target_dir, nc::AT_REMOVEDIR) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mount<P: AsRef<Path>>(
    dev_name: P,
    dir_name: P,
    fs_type: P,
    flags: usize,
    data: usize,
) -> Result<(), Errno> {
    let dev_name = CString::new(dev_name.as_ref());
    let dev_name_ptr = dev_name.as_ptr() as usize;
    let dir_name = CString::new(dir_name.as_ref());
    let dir_name_ptr = dir_name.as_ptr() as usize;
    let fs_type = CString::new(fs_type.as_ref());
    let fs_type_ptr = fs_type.as_ptr() as usize;
    syscall5(
        SYS_MOUNT,
        dev_name_ptr,
        dir_name_ptr,
        fs_type_ptr,
        flags,
        data,
    )
    .map(drop)
}

/// Set protection on a region of memory.
///
/// # Example
///
/// ```
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let addr = unsafe {
///     nc::mmap(
///         0,
///         map_length,
///         nc::PROT_READ | nc::PROT_WRITE,
///         nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
///         -1,
///         0,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// // Set the third page readonly. And we will run into SIGSEGV when updating it.
/// let ret = unsafe { nc::mprotect(addr + 2 * nc::PAGE_SIZE, nc::PAGE_SIZE, nc::PROT_READ) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mprotect(addr: usize, len: size_t, prot: i32) -> Result<(), Errno> {
    let prot = prot as usize;
    syscall3(SYS_MPROTECT, addr, len, prot).map(drop)
}

/// System V message control operations.
///
/// # Example
///
/// ```
/// let key = nc::IPC_PRIVATE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
/// let ret = unsafe { nc::msgget(key, flags) };
/// assert!(ret.is_ok());
/// let msq_id = ret.unwrap();

/// let mut buf = nc::msqid_ds_t::default();
/// let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn msgctl(msqid: i32, cmd: i32, buf: &mut msqid_ds_t) -> Result<i32, Errno> {
    let msqid = msqid as usize;
    let cmd = cmd as usize;
    let buf_ptr = buf as *mut msqid_ds_t as usize;
    syscall3(SYS_MSGCTL, msqid, cmd, buf_ptr).map(|ret| ret as i32)
}

/// Get a System V message queue identifier.
///
/// # Example
///
/// ```
/// let key = nc::IPC_PRIVATE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
/// let ret = unsafe { nc::msgget(key, flags) };
/// assert!(ret.is_ok());
/// let msq_id = ret.unwrap();

/// let mut buf = nc::msqid_ds_t::default();
/// let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn msgget(key: key_t, msgflg: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let msgflg = msgflg as usize;
    syscall2(SYS_MSGGET, key, msgflg).map(|ret| ret as i32)
}

/// Receive messages from a System V message queue.
///
/// # Example
///
/// ```
/// const MAX_MTEXT: usize = 1024;
///
/// const MTYPE_NULL: isize = 0;
/// const MTYPE_CLIENT: isize = 1;
/// const _MTYPE_SERVER: isize = 2;
///
/// #[derive(Debug, Clone, Copy)]
/// struct Message {
///     pub mtype: isize,
///     pub mtext: [u8; MAX_MTEXT],
/// }
///
/// impl Default for Message {
///     fn default() -> Self {
///         Message {
///             mtype: MTYPE_NULL,
///             mtext: [0; MAX_MTEXT],
///         }
///     }
/// }
///
/// fn main() {
///     let key = nc::IPC_PRIVATE;
///     let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
///     let ret = unsafe { nc::msgget(key, flags) };
///     assert!(ret.is_ok());
///     let msq_id = ret.unwrap();
///
///     // Write to message queue.
///     let msg = "Hello, Rust";
///     let mut client_msg = Message {
///         mtype: MTYPE_CLIENT,
///         mtext: [0; MAX_MTEXT],
///     };
///     let msg_len = msg.len();
///     unsafe {
///         let src_ptr = msg.as_ptr();
///         let dst_ptr = client_msg.mtext.as_mut_ptr();
///         core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, msg_len);
///     }
///
///     let ret = unsafe { nc::msgsnd(msq_id, &client_msg as *const Message as usize, msg_len, 0) };
///     assert!(ret.is_ok());
///
///     // Read from message queue.
///     let mut recv_msg = Message::default();
///     let ret = unsafe {
///         nc::msgrcv(
///             msq_id,
///             &mut recv_msg as *mut Message as usize,
///             MAX_MTEXT,
///             MTYPE_CLIENT,
///             0,
///         )
///     };
///     assert!(ret.is_ok());
///     let recv_msg_len = ret.unwrap() as usize;
///     assert_eq!(recv_msg_len, msg_len);
///     let recv_text = core::str::from_utf8(&recv_msg.mtext[..recv_msg_len]);
///     assert!(recv_text.is_ok());
///     let recv_text = recv_text.unwrap();
///     assert_eq!(recv_text, msg);
///     println!("recv text: {}", recv_text);
///
///     let mut buf = nc::msqid_ds_t::default();
///     let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
///     assert!(ret.is_ok());
/// }
/// ```
pub unsafe fn msgrcv(
    msqid: i32,
    msgq: usize,
    msgsz: size_t,
    msgtyp: isize,
    msgflg: i32,
) -> Result<ssize_t, Errno> {
    let msqid = msqid as usize;
    let msgtyp = msgtyp as usize;
    let msgflg = msgflg as usize;
    syscall5(SYS_MSGRCV, msqid, msgq, msgsz, msgtyp, msgflg).map(|ret| ret as ssize_t)
}

/// Append the message to a System V message queue.
///
/// # Example
///
/// ```
/// const MAX_MTEXT: usize = 1024;
///
/// const MTYPE_NULL: isize = 0;
/// const MTYPE_CLIENT: isize = 1;
/// const _MTYPE_SERVER: isize = 2;
///
/// #[derive(Debug, Clone, Copy)]
/// struct Message {
///     pub mtype: isize,
///     pub mtext: [u8; MAX_MTEXT],
/// }
///
/// impl Default for Message {
///     fn default() -> Self {
///         Message {
///             mtype: MTYPE_NULL,
///             mtext: [0; MAX_MTEXT],
///         }
///     }
/// }
///
/// fn main() {
///     let key = nc::IPC_PRIVATE;
///     let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
///     let ret = unsafe { nc::msgget(key, flags) };
///     assert!(ret.is_ok());
///     let msq_id = ret.unwrap();
///
///     // Write to message queue.
///     let msg = "Hello, Rust";
///     let mut client_msg = Message {
///         mtype: MTYPE_CLIENT,
///         mtext: [0; MAX_MTEXT],
///     };
///     let msg_len = msg.len();
///     unsafe {
///         let src_ptr = msg.as_ptr();
///         let dst_ptr = client_msg.mtext.as_mut_ptr();
///         core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, msg_len);
///     }
///
///     let ret = unsafe { nc::msgsnd(msq_id, &client_msg as *const Message as usize, msg_len, 0) };
///     assert!(ret.is_ok());
///
///     // Read from message queue.
///     let mut recv_msg = Message::default();
///     let ret = unsafe {
///         nc::msgrcv(
///             msq_id,
///             &mut recv_msg as *mut Message as usize,
///             MAX_MTEXT,
///             MTYPE_CLIENT,
///             0,
///         )
///     };
///     assert!(ret.is_ok());
///     let recv_msg_len = ret.unwrap() as usize;
///     assert_eq!(recv_msg_len, msg_len);
///     let recv_text = core::str::from_utf8(&recv_msg.mtext[..recv_msg_len]);
///     assert!(recv_text.is_ok());
///     let recv_text = recv_text.unwrap();
///     assert_eq!(recv_text, msg);
///
///     let mut buf = nc::msqid_ds_t::default();
///     let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
///     assert!(ret.is_ok());
/// }
/// ```
pub unsafe fn msgsnd(msqid: i32, msgq: usize, msgsz: size_t, msgflg: i32) -> Result<(), Errno> {
    let msqid = msqid as usize;
    let msgflg = msgflg as usize;
    syscall4(SYS_MSGSND, msqid, msgq, msgsz, msgflg).map(drop)
}

/// Synchronize a file with memory map.
pub unsafe fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    syscall3(SYS_MSYNC, addr, len, flags).map(drop)
}

/// Unlock memory.
///
/// # Example
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let addr = passwd_buf.as_ptr() as usize;
/// let ret = unsafe { nc::mlock2(addr, passwd_buf.len(), nc::MCL_CURRENT) };
/// for i in 0..passwd_buf.len() {
///   passwd_buf[i] = i as u8;
/// }
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::munlock(addr, passwd_buf.len()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlock(addr: usize, len: size_t) -> Result<(), Errno> {
    syscall2(SYS_MUNLOCK, addr, len).map(drop)
}

/// Unlock memory.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::mlockall(nc::MCL_CURRENT) };
/// assert!(ret.is_ok() || ret == Err(nc::ENOMEM));
/// let ret = unsafe { nc::munlockall() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlockall() -> Result<(), Errno> {
    syscall0(SYS_MUNLOCKALL).map(drop)
}

/// Unmap files or devices from memory.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let mut sb = nc::stat_t::default();
/// let ret = unsafe { nc::fstat(fd, &mut sb) };
/// assert!(ret.is_ok());
///
/// let offset: usize = 0;
/// let length: usize = sb.st_size as usize - offset;
/// // Offset for mmap must be page aligned.
/// let pa_offset: usize = offset & !(nc::PAGE_SIZE - 1);
/// let map_length = length + offset - pa_offset;
///
/// let addr = unsafe {
///     nc::mmap(
///         0, // 0 as NULL
///         map_length,
///         nc::PROT_READ,
///         nc::MAP_PRIVATE,
///         fd,
///         pa_offset as nc::off_t,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// let n_write = unsafe { nc::write(1, addr + offset - pa_offset, length) };
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munmap(addr: usize, len: size_t) -> Result<(), Errno> {
    syscall2(SYS_MUNMAP, addr, len).map(drop)
}

/// High resolution sleep.
///
/// # Example
///
/// ```
/// let t = nc::timespec_t {
///     tv_sec: 1,
///     tv_nsec: 0,
/// };
/// let ret = unsafe { nc::nanosleep(&t, None) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn nanosleep(req: &timespec_t, rem: Option<&mut timespec_t>) -> Result<(), Errno> {
    let req_ptr = req as *const timespec_t as usize;
    let rem_ptr = rem.map_or(0, |rem| rem as *mut timespec_t as usize);
    syscall2(SYS_NANOSLEEP, req_ptr, rem_ptr).map(drop)
}

/// Open and possibly create a file.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::open(path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn open<P: AsRef<Path>>(filename: P, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    syscall3(SYS_OPEN, filename_ptr, flags, mode).map(|ret| ret as i32)
}

/// Open and possibly create a file within a directory.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn openat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    flags: i32,
    mode: mode_t,
) -> Result<i32, Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    syscall4(SYS_OPENAT, dirfd, filename_ptr, flags, mode).map(|ret| ret as i32)
}

/// Create a pipe.
///
/// # Example
///
/// ```
/// let mut fds = [-1_i32, 2];
/// let ret = unsafe {nc::pipe2(&mut fds, nc::O_CLOEXEC | nc::O_NONBLOCK) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fds[0]) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fds[1]) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pipe2(pipefd: &mut [i32; 2], flags: i32) -> Result<(), Errno> {
    let pipefd_ptr = pipefd.as_mut_ptr() as usize;
    let flags = flags as usize;
    syscall2(SYS_PIPE2, pipefd_ptr, flags).map(drop)
}

/// Wait for some event on file descriptors.
pub unsafe fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<(), Errno> {
    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len();
    let timeout = timeout as usize;
    syscall3(SYS_POLL, fds_ptr, nfds, timeout).map(drop)
}

/// Wait for some event on a file descriptor.
pub unsafe fn ppoll(
    fds: &mut pollfd_t,
    nfds: i32,
    timeout: &timespec_t,
    sigmask: &sigset_t,
    sigsetsize: size_t,
) -> Result<i32, Errno> {
    let fds_ptr = fds as *mut pollfd_t as usize;
    let nfds = nfds as usize;
    let timeout_ptr = timeout as *const timespec_t as usize;
    let sigmask_ptr = sigmask as *const sigset_t as usize;
    syscall5(
        SYS_PPOLL,
        fds_ptr,
        nfds,
        timeout_ptr,
        sigmask_ptr,
        sigsetsize,
    )
    .map(|ret| ret as i32)
}

/// Read from a file descriptor without changing file offset.
///
/// # Example
///
/// ```
/// use core::ffi::c_void;
///
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as *const c_void,
///     });
/// }
/// let iov_len = iov.len();
/// let ret = unsafe { nc::preadv(fd, &mut iov, 0, iov_len - 1) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn preadv(
    fd: i32,
    vec: &mut [iovec_t],
    pos_l: usize,
    pos_h: usize,
) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let vec_ptr = vec.as_mut_ptr() as usize;
    let vec_len = vec.len();
    syscall5(SYS_PREADV, fd, vec_ptr, vec_len, pos_l, pos_h).map(|ret| ret as ssize_t)
}

/// Process trace.
pub unsafe fn ptrace(request: i32, pid: pid_t, addr: usize, data: usize) -> Result<isize, Errno> {
    let request = request as usize;
    let pid = pid as usize;
    syscall4(SYS_PTRACE, request, pid, addr, data).map(|ret| ret as isize)
}

/// Write to a file descriptor without changing file offset.
///
/// # Example
///
/// ```
/// use core::ffi::c_void;
///
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as *const c_void,
///     });
/// }
/// let ret = unsafe { nc::readv(fd, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
///
/// let path_out = "/tmp/nc-pwritev";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path_out, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::pwritev(fd, &iov, 0, iov.len() - 1) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path_out, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pwritev(
    fd: i32,
    vec: &[iovec_t],
    pos_l: usize,
    pos_h: usize,
) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let vec_ptr = vec.as_ptr() as usize;
    let vec_len = vec.len();
    syscall5(SYS_PWRITEV, fd, vec_ptr, vec_len, pos_l, pos_h).map(|ret| ret as ssize_t)
}

/// Manipulate disk quotes.
pub unsafe fn quotactl<P: AsRef<Path>>(
    path: P,
    cmd: i32,
    id: i32,
    addr: usize,
) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let cmd = cmd as usize;
    let id = id as usize;
    syscall4(SYS_QUOTACTL, path_ptr, cmd, id, addr).map(drop)
}

/// Read from a file descriptor.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [0_u8; 4 * 1024];
/// let ret = unsafe { nc::read(fd, buf.as_mut_ptr() as usize, buf.len()) };
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap();
/// assert!(n_read <= buf.len() as nc::ssize_t);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn read(fd: i32, buf_ptr: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_READ, fd, buf_ptr, count).map(|ret| ret as ssize_t)
}

/// Read value of a symbolic link.
///
/// # Example
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlink";
/// let ret = unsafe { nc::symlinkat(oldname, nc::AT_FDCWD, newname) };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::readlink(newname, &mut buf, buf_len) };
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap() as usize;
/// assert_eq!(n_read, oldname.len());
/// assert_eq!(oldname.as_bytes(), &buf[0..n_read]);
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn readlink<P: AsRef<Path>>(
    filename: P,
    buf: &mut [u8],
    buf_len: size_t,
) -> Result<ssize_t, Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    syscall3(SYS_READLINK, filename_ptr, buf_ptr, buf_len).map(|ret| ret as ssize_t)
}

/// Read value of a symbolic link.
///
/// # Example
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlinkat";
/// let ret = unsafe { nc::symlinkat(oldname, nc::AT_FDCWD, newname) };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::readlinkat(nc::AT_FDCWD, newname, &mut buf, buf_len) };
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap() as usize;
/// assert_eq!(n_read, oldname.len());
/// assert_eq!(oldname.as_bytes(), &buf[0..n_read]);
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn readlinkat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    buf: &mut [u8],
    buf_len: size_t,
) -> Result<ssize_t, Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    syscall4(SYS_READLINKAT, dirfd, filename_ptr, buf_ptr, buf_len).map(|ret| ret as ssize_t)
}

/// Read from a file descriptor into multiple buffers.
///
/// # Example
///
/// ```
/// use core::ffi::c_void;
///
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
/// // TODO(Shaohua): Replace with as_mut_ptr()
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as *const c_void,
///     });
/// }
/// let ret = unsafe { nc::readv(fd, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn readv(fd: i32, iov: &mut [iovec_t]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let iov_ptr = iov.as_mut_ptr() as usize;
    let len = iov.len();
    syscall3(SYS_READV, fd, iov_ptr, len).map(|ret| ret as ssize_t)
}

/// Reboot or enable/disable Ctrl-Alt-Del.
///
/// # Example
///
/// ```
/// let ret = unsafe {
///     nc::reboot(
///         nc::LINUX_REBOOT_MAGIC1,
///         nc::LINUX_REBOOT_MAGIC2,
///         nc::LINUX_REBOOT_CMD_RESTART,
///         0
///     )
/// };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn reboot(magic: i32, magci2: i32, cmd: u32, arg: usize) -> Result<(), Errno> {
    let magic = magic as usize;
    let magic2 = magci2 as usize;
    let cmd = cmd as usize;
    syscall4(SYS_REBOOT, magic, magic2, cmd, arg).map(drop)
}

/// Receive a message from a socket.
pub unsafe fn recvfrom(
    sockfd: i32,
    buf: &mut [u8],
    flags: i32,
    src_addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buflen = buf.len();
    let flags = flags as usize;
    let src_addr_ptr = src_addr as *mut sockaddr_in_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall6(
        SYS_RECVFROM,
        sockfd,
        buf_ptr,
        buflen,
        flags,
        src_addr_ptr,
        addrlen_ptr,
    )
    .map(|ret| ret as ssize_t)
}

/// Receive a msg from a socket.
pub unsafe fn recvmsg(sockfd: i32, msg: &mut msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = msg as *mut msghdr_t as usize;
    let flags = flags as usize;
    syscall3(SYS_RECVMSG, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t)
}

/// Change name or location of a file.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-rename";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let new_path = "/tmp/nc-rename-new";
/// let ret = unsafe { nc::rename(path, new_path) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, new_path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn rename<P: AsRef<Path>>(oldfilename: P, newfilename: P) -> Result<(), Errno> {
    let oldfilename = CString::new(oldfilename.as_ref());
    let oldfilename_ptr = oldfilename.as_ptr() as usize;
    let newfilename = CString::new(newfilename.as_ref());
    let newfilename_ptr = newfilename.as_ptr() as usize;
    syscall2(SYS_RENAME, oldfilename_ptr, newfilename_ptr).map(drop)
}

/// Change name or location of a file.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-renameat";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let new_path = "/tmp/nc-renameat-new";
/// let ret = unsafe { nc::renameat(nc::AT_FDCWD, path, nc::AT_FDCWD, new_path) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, new_path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn renameat<P: AsRef<Path>>(
    olddfd: i32,
    oldfilename: P,
    newdfd: i32,
    newfilename: P,
) -> Result<(), Errno> {
    let olddfd = olddfd as usize;
    let oldfilename = CString::new(oldfilename.as_ref());
    let oldfilename_ptr = oldfilename.as_ptr() as usize;
    let newdfd = newdfd as usize;
    let newfilename = CString::new(newfilename.as_ref());
    let newfilename_ptr = newfilename.as_ptr() as usize;
    syscall4(
        SYS_RENAMEAT,
        olddfd,
        oldfilename_ptr,
        newdfd,
        newfilename_ptr,
    )
    .map(drop)
}

/// Delete a directory.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-rmdir";
/// let ret = unsafe { nc::mkdirat(nc::AT_FDCWD, path, 0o755) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::rmdir(path) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn rmdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_RMDIR, filename_ptr).map(drop)
}

/// Get scheduling paramters.
///
/// # Example
///
/// ```
/// let mut param = nc::sched_param_t::default();
/// let ret = unsafe { nc::sched_getparam(0, &mut param) };
/// assert!(ret.is_ok());
/// assert_eq!(param.sched_priority, 0);
/// ```
pub unsafe fn sched_getparam(pid: pid_t, param: &mut sched_param_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let param_ptr = param as *mut sched_param_t as usize;
    syscall2(SYS_SCHED_GETPARAM, pid, param_ptr).map(drop)
}

/// Get scheduling parameter.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::sched_getscheduler(0) };
/// assert_eq!(ret, Ok(nc::SCHED_NORMAL));
/// ```
pub unsafe fn sched_getscheduler(pid: pid_t) -> Result<i32, Errno> {
    let pid = pid as usize;
    syscall1(SYS_SCHED_GETSCHEDULER, pid).map(|ret| ret as i32)
}

/// Get static priority max value.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::sched_get_priority_max(nc::SCHED_RR) };
/// assert!(ret.is_ok());
/// let max_prio = ret.unwrap();
/// assert_eq!(max_prio, 99);
/// ```
pub unsafe fn sched_get_priority_max(policy: i32) -> Result<i32, Errno> {
    let policy = policy as usize;
    syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy).map(|ret| ret as i32)
}

/// Get static priority min value.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::sched_get_priority_min(nc::SCHED_RR) };
/// assert!(ret.is_ok());
/// let min_prio = ret.unwrap();
/// assert_eq!(min_prio, 1);
/// ```
pub unsafe fn sched_get_priority_min(policy: i32) -> Result<i32, Errno> {
    let policy = policy as usize;
    syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy).map(|ret| ret as i32)
}

/// Get the `SCHED_RR` interval for the named process.
///
/// # Example
///
/// ```
/// let mut ts = nc::timespec_t::default();
/// let ret = unsafe { nc::sched_rr_get_interval(0, &mut ts) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sched_rr_get_interval(pid: pid_t, interval: &mut timespec_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let interval_ptr = interval as *mut timespec_t as usize;
    syscall2(SYS_SCHED_RR_GET_INTERVAL, pid, interval_ptr).map(drop)
}

/// Set scheduling paramters.
///
/// # Example
///
/// ```
/// // This call always returns error because default scheduler is SCHED_NORMAL.
/// // We shall call sched_setscheduler() and change to realtime policy
/// // like SCHED_RR or SCHED_FIFO.
/// let sched_param = nc::sched_param_t { sched_priority: 12 };
/// let ret = unsafe { nc::sched_setparam(0, &sched_param) };
/// assert_eq!(ret, Err(nc::EINVAL));
/// ```
pub unsafe fn sched_setparam(pid: pid_t, param: &sched_param_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let param_ptr = param as *const sched_param_t as usize;
    syscall2(SYS_SCHED_SETPARAM, pid, param_ptr).map(drop)
}

/// Set scheduling parameter.
///
/// # Example
///
/// ```
/// let sched_param = nc::sched_param_t { sched_priority: 12 };
/// let ret = unsafe { nc::sched_setscheduler(0, nc::SCHED_RR, &sched_param) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn sched_setscheduler(
    pid: pid_t,
    policy: i32,
    param: &sched_param_t,
) -> Result<(), Errno> {
    let pid = pid as usize;
    let policy = policy as usize;
    let param_ptr = param as *const sched_param_t as usize;
    syscall3(SYS_SCHED_SETSCHEDULER, pid, policy, param_ptr).map(drop)
}

/// Yield the processor.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::sched_yield() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sched_yield() -> Result<(), Errno> {
    syscall0(SYS_SCHED_YIELD).map(drop)
}

/// Sychronous I/O multiplexing.
pub unsafe fn select(
    nfds: i32,
    readfds: &mut fd_set_t,
    writefds: &mut fd_set_t,
    exceptfds: &mut fd_set_t,
    timeout: &mut timeval_t,
) -> Result<i32, Errno> {
    let nfds = nfds as usize;
    let readfds_ptr = readfds as *mut fd_set_t as usize;
    let writefds_ptr = writefds as *mut fd_set_t as usize;
    let exceptfds_ptr = exceptfds as *mut fd_set_t as usize;
    let timeout_ptr = timeout as *mut timeval_t as usize;
    syscall5(
        SYS_SELECT,
        nfds,
        readfds_ptr,
        writefds_ptr,
        exceptfds_ptr,
        timeout_ptr,
    )
    .map(|ret| ret as i32)
}

/// Get a System V semphore set identifier.
pub unsafe fn semget(key: key_t, nsems: i32, semflg: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let nsems = nsems as usize;
    let semflg = semflg as usize;
    syscall3(SYS_SEMGET, key, nsems, semflg).map(|ret| ret as i32)
}

/// System V semphore operations.
pub unsafe fn semop(semid: i32, sops: &mut [sembuf_t]) -> Result<(), Errno> {
    let semid = semid as usize;
    let sops_ptr = sops.as_ptr() as usize;
    let nops = sops.len();
    syscall3(SYS_SEMOP, semid, sops_ptr, nops).map(drop)
}

/// Transfer data between two file descriptors.
pub unsafe fn sendfile(
    out_fd: i32,
    in_fd: i32,
    offset: &mut off_t,
    count: size_t,
) -> Result<ssize_t, Errno> {
    let out_fd = out_fd as usize;
    let in_fd = in_fd as usize;
    let offset_ptr = offset as *mut off_t as usize;
    syscall4(SYS_SENDFILE, out_fd, in_fd, offset_ptr, count).map(|ret| ret as ssize_t)
}

/// Send a message on a socket. Allow sending ancillary data.
pub unsafe fn sendmsg(sockfd: i32, msg: &msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = msg as *const msghdr_t as usize;
    let flags = flags as usize;
    syscall3(SYS_SENDMSG, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t)
}

/// Send a message on a socket.
pub unsafe fn sendto(
    sockfd: i32,
    buf: &[u8],
    len: size_t,
    flags: i32,
    dest_addr: &sockaddr_in_t,
    addrlen: socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let flags = flags as usize;
    let dest_addr_ptr = dest_addr as *const sockaddr_in_t as usize;
    let addrlen = addrlen as usize;
    syscall6(
        SYS_SENDTO,
        sockfd,
        buf_ptr,
        len,
        flags,
        dest_addr_ptr,
        addrlen,
    )
    .map(|ret| ret as ssize_t)
}

/// Set the group ID of the calling process to `gid`.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setgid(0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setgid(gid: gid_t) -> Result<(), Errno> {
    let gid = gid as usize;
    syscall1(SYS_SETGID, gid).map(drop)
}

/// Set list of supplementary group Ids.
///
/// # Example
///
/// ```
/// let list = [0, 1, 2];
/// let ret = unsafe { nc::setgroups(&list) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setgroups(group_list: &[gid_t]) -> Result<(), Errno> {
    let group_len = group_list.len();
    let group_ptr = group_list.as_ptr() as usize;
    syscall2(SYS_SETGROUPS, group_len, group_ptr).map(drop)
}

/// Set value of an interval timer.
///
/// # Example
///
/// ```
/// use core::mem::size_of;
///
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
///     let msg = "Hello alarm";
///     let _ = unsafe { nc::write(2, msg.as_ptr() as usize, msg.len()) };
/// }
///
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     sa_flags: 0,
///     ..nc::sigaction_t::default()
/// };
/// let mut old_sa = nc::sigaction_t::default();
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>()) };
/// assert!(ret.is_ok());
///
/// // Single shot timer, actived after 1 second.
/// let itv = nc::itimerval_t {
///     it_value: nc::timeval_t {
///         tv_sec: 1,
///         tv_usec: 0,
///     },
///     it_interval: nc::timeval_t {
///         tv_sec: 0,
///         tv_usec: 0,
///     },
/// };
/// let mut prev_itv = nc::itimerval_t::default();
/// let ret = unsafe { nc::setitimer(nc::ITIMER_REAL, &itv, &mut prev_itv) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);
///
/// let mask = nc::sigset_t::default();
/// let _ret = unsafe { nc::rt_sigsuspend(&mask, size_of::<nc::sigset_t>()) };
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert_eq!(prev_itv.it_value.tv_sec, 0);
/// assert_eq!(prev_itv.it_value.tv_usec, 0);
/// ```
pub unsafe fn setitimer(
    which: i32,
    new_val: &itimerval_t,
    old_val: &mut itimerval_t,
) -> Result<(), Errno> {
    let which = which as usize;
    let new_val_ptr = new_val as *const itimerval_t as usize;
    let old_val_ptr = old_val as *mut itimerval_t as usize;
    syscall3(SYS_SETITIMER, which, new_val_ptr, old_val_ptr).map(drop)
}

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setpgid(nc::getpid(), 1) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let pgid = pgid as usize;
    syscall2(SYS_SETPGID, pid, pgid).map(drop)
}

/// Set program scheduling priority.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setpriority(nc::PRIO_PROCESS, nc::getpid(), -19) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EACCES))
/// ```
pub unsafe fn setpriority(which: i32, who: i32, prio: i32) -> Result<(), Errno> {
    let which = which as usize;
    let who = who as usize;
    let prio = prio as usize;
    syscall3(SYS_SETPRIORITY, which, who, prio).map(drop)
}

/// Set real and effective group IDs of the calling process.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setregid(0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setregid(rgid: gid_t, egid: gid_t) -> Result<(), Errno> {
    let rgid = rgid as usize;
    let egid = egid as usize;
    syscall2(SYS_SETREGID, rgid, egid).map(drop)
}

/// Set real, effective and saved group Ids of the calling process.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setresgid(0, 0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<(), Errno> {
    let rgid = rgid as usize;
    let egid = egid as usize;
    let sgid = sgid as usize;
    syscall3(SYS_SETRESGID, rgid, egid, sgid).map(drop)
}

/// Set real, effective and saved user Ids of the calling process.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setresuid(0, 0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<(), Errno> {
    let ruid = ruid as usize;
    let euid = euid as usize;
    let suid = suid as usize;
    syscall3(SYS_SETRESUID, ruid, euid, suid).map(drop)
}

/// Set real and effective user IDs of the calling process.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setreuid(0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), Errno> {
    let ruid = ruid as usize;
    let euid = euid as usize;
    syscall2(SYS_SETREUID, ruid, euid).map(drop)
}

/// Set resource limit.
///
/// # Example
///
/// ```
/// let rlimit = nc::rlimit_t {
///     rlim_cur: 128,
///     rlim_max: 128,
/// };
/// let ret = unsafe { nc::setrlimit(nc::RLIMIT_NOFILE, &rlimit) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setrlimit(resource: i32, rlimit: &rlimit_t) -> Result<(), Errno> {
    let resource = resource as usize;
    let rlimit_ptr = rlimit as *const rlimit_t as usize;
    syscall2(SYS_SETRLIMIT, resource, rlimit_ptr).map(drop)
}

/// Create a new session if the calling process is not a process group leader.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setsid() };
/// assert!(ret.is_ok());
/// let pid = unsafe { nc::getpid() };
/// assert_eq!(ret, Ok(pid));
/// ```
pub unsafe fn setsid() -> Result<pid_t, Errno> {
    syscall0(SYS_SETSID).map(|ret| ret as pid_t)
}

/// Set options on sockets.
///
/// # Example
///
/// ```
/// let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
/// assert!(socket_fd.is_ok());
/// let socket_fd = socket_fd.unwrap();
///
/// // Enable tcp fast open.
/// let queue_len: i32 = 5;
/// let queue_len_ptr = &queue_len as *const i32 as usize;
/// let ret = unsafe {
///     nc::setsockopt(
///         socket_fd,
///         nc::IPPROTO_TCP,
///         nc::TCP_FASTOPEN,
///         queue_len_ptr,
///         std::mem::size_of_val(&queue_len) as u32,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(socket_fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setsockopt(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: usize,
    optlen: socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let optname = optname as usize;
    let optlen = optlen as usize;
    syscall5(SYS_SETSOCKOPT, sockfd, level, optname, optval, optlen).map(drop)
}

/// Set system time and timezone.
///
/// ```
/// let tv = nc::timeval_t {
///     tv_sec: 0,
///     tv_usec: 0,
/// };
/// let tz = nc::timezone_t::default();
/// let ret = unsafe { nc::settimeofday(&tv, &tz) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn settimeofday(timeval: &timeval_t, tz: &timezone_t) -> Result<(), Errno> {
    let timeval_ptr = timeval as *const timeval_t as usize;
    let tz_ptr = tz as *const timezone_t as usize;
    syscall2(SYS_SETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop)
}

/// Set the effective user ID of the calling process to `uid`.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setuid(0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setuid(uid: uid_t) -> Result<(), Errno> {
    let uid = uid as usize;
    syscall1(SYS_SETUID, uid).map(drop)
}

/// Attach the System V shared memory segment.
///
/// # Example
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let shmid = ret.unwrap();
///
/// let addr: usize = 0;
/// let ret = unsafe { nc::shmat(shmid, addr, 0) };
/// assert!(ret.is_ok());
/// let addr = ret.unwrap();
///
/// let mut buf = nc::shmid_ds_t::default();
/// let ret = unsafe { nc::shmctl(shmid, nc::IPC_STAT, &mut buf) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::shmdt(addr) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::shmctl(shmid, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> Result<usize, Errno> {
    let shmid = shmid as usize;
    let shmflg = shmflg as usize;
    syscall3(SYS_SHMAT, shmid, shmaddr, shmflg)
}

/// System V shared memory control.
///
/// # Example
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let shmid = ret.unwrap();
/// let mut buf = nc::shmid_ds_t::default();
/// let ret = unsafe { nc::shmctl(shmid, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn shmctl(shmid: i32, cmd: i32, buf: &mut shmid_ds_t) -> Result<i32, Errno> {
    let shmid = shmid as usize;
    let cmd = cmd as usize;
    let buf_ptr = buf as *mut shmid_ds_t as usize;
    syscall3(SYS_SHMCTL, shmid, cmd, buf_ptr).map(|ret| ret as i32)
}

/// Detach the System V shared memory segment.
///
/// # Example
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let shmid = ret.unwrap();
///
/// let addr: usize = 0;
/// let ret = unsafe { nc::shmat(shmid, addr, 0) };
/// assert!(ret.is_ok());
/// let addr = ret.unwrap();
///
/// let mut buf = nc::shmid_ds_t::default();
/// let ret = unsafe { nc::shmctl(shmid, nc::IPC_STAT, &mut buf) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::shmdt(addr) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::shmctl(shmid, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn shmdt(shmaddr: usize) -> Result<(), Errno> {
    syscall1(SYS_SHMDT, shmaddr).map(drop)
}

/// Allocates a System V shared memory segment.
///
/// # Example
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let _shmid = ret.unwrap();
/// ```
pub unsafe fn shmget(key: key_t, size: size_t, shmflg: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let shmflg = shmflg as usize;
    syscall3(SYS_SHMGET, key, size, shmflg).map(|ret| ret as i32)
}

/// Shutdown part of a full-duplex connection.
pub unsafe fn shutdown(sockfd: i32, how: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let how = how as usize;
    syscall2(SYS_SHUTDOWN, sockfd, how).map(drop)
}

/// Examine and change a signal action.
pub unsafe fn sigaction(
    sig: i32,
    act: &sigaction_t,
    old_act: &mut sigaction_t,
) -> Result<(), Errno> {
    let sig = sig as usize;
    let act_ptr = act as *const sigaction_t as usize;
    let old_act_ptr = old_act as *mut sigaction_t as usize;
    syscall3(SYS_SIGACTION, sig, act_ptr, old_act_ptr).map(drop)
}

/// Get/set signal stack context.
pub unsafe fn sigaltstack(uss: &sigaltstack_t, uoss: &mut sigaltstack_t) -> Result<(), Errno> {
    let uss_ptr = uss as *const sigaltstack_t as usize;
    let uoss_ptr = uoss as *mut sigaltstack_t as usize;
    syscall2(SYS_SIGALTSTACK, uss_ptr, uoss_ptr).map(drop)
}

/// Examine pending signals.
pub unsafe fn sigpending(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = set as *mut sigset_t as usize;
    syscall1(SYS_SIGPENDING, set_ptr).map(drop)
}

/// Examine and change blocked signals.
pub unsafe fn sigprocmask(
    how: i32,
    newset: &mut sigset_t,
    oldset: &mut sigset_t,
) -> Result<(), Errno> {
    let how = how as usize;
    let newset_ptr = newset as *mut sigset_t as usize;
    let oldset_ptr = oldset as *mut sigset_t as usize;
    syscall3(SYS_SIGPROCMASK, how, newset_ptr, oldset_ptr).map(drop)
}

/// Return from signal handler and cleanup stack frame.
/// Never returns.
pub unsafe fn sigreturn() {
    let _ = syscall0(SYS_SIGRETURN);
}

/// Wait for a signal.
///
/// # Example
/// ```
/// let pid = unsafe { nc::fork() };
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
///
/// if pid == 0 {
///     // child process.
///     let mask = nc::sigset_t::default();
///     let ret = unsafe { nc::sigsuspend(&mask) };
///     assert!(ret.is_ok());
/// } else {
///     // parent process.
///     let t = nc::timespec_t {
///         tv_sec: 1,
///         tv_nsec: 0,
///     };
///     let ret = unsafe { nc::nanosleep(&t, None) };
///     assert!(ret.is_ok());
///
///     let ret = unsafe { nc::kill(pid, nc::SIGTERM) };
///     assert!(ret.is_ok());
/// }
/// ```
pub unsafe fn sigsuspend(mask: &old_sigset_t) -> Result<(), Errno> {
    let mask_ptr = mask as *const old_sigset_t as usize;
    syscall1(SYS_SIGSUSPEND, mask_ptr).map(drop)
}

/// Create an endpoint for communication.
///
/// # Example
///
/// ```
/// let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
/// assert!(socket_fd.is_ok());
/// let socket_fd = socket_fd.unwrap();
/// let ret = unsafe { nc::close(socket_fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn socket(domain: i32, sock_type: i32, protocol: i32) -> Result<i32, Errno> {
    let domain = domain as usize;
    let sock_type = sock_type as usize;
    let protocol = protocol as usize;
    syscall3(SYS_SOCKET, domain, sock_type, protocol).map(|ret| ret as i32)
}

/// Create a pair of connected socket.
pub unsafe fn socketpair(
    domain: i32,
    type_: i32,
    protocol: i32,
    sv: [i32; 2],
) -> Result<(), Errno> {
    let domain = domain as usize;
    let type_ = type_ as usize;
    let protocol = protocol as usize;
    let sv_ptr = sv.as_ptr() as usize;
    syscall4(SYS_SOCKETPAIR, domain, type_, protocol, sv_ptr).map(drop)
}

/// Get filesystem statistics.
///
/// # Example
///
/// ```
/// let path = "/usr";
/// let mut statfs = nc::statfs_t::default();
/// let ret = unsafe { nc::statfs(path, &mut statfs) };
/// assert!(ret.is_ok());
/// assert!(statfs.f_bfree > 0);
/// assert!(statfs.f_bavail > 0);
/// ```
pub unsafe fn statfs<P: AsRef<Path>>(filename: P, buf: &mut statfs_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = buf as *mut statfs_t as usize;
    syscall2(SYS_STATFS, filename_ptr, buf_ptr).map(drop)
}

/// Stop swapping to file/device.
///
/// # Example
///
/// ```
/// let filename = "/dev/sda-no-exist";
/// let ret = unsafe { nc::swapoff(filename) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn swapoff<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_SWAPOFF, filename_ptr).map(drop)
}

/// Start swapping to file/device.
///
/// # Example
///
/// ```
/// let filename = "/dev/sda-no-exist";
/// let ret = unsafe { nc::swapon(filename, nc::SWAP_FLAG_PREFER) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn swapon<P: AsRef<Path>>(filename: P, flags: i32) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flags = flags as usize;
    syscall2(SYS_SWAPON, filename_ptr, flags).map(drop)
}

/// Make a new name for a file.
///
/// # Example
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-symlink";
/// let ret = unsafe { nc::symlink(oldname, newname) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname,0 ) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn symlink<P: AsRef<Path>>(oldname: P, newname: P) -> Result<(), Errno> {
    let oldname = CString::new(oldname.as_ref());
    let oldname_ptr = oldname.as_ptr() as usize;
    let newname = CString::new(newname.as_ref());
    let newname_ptr = newname.as_ptr() as usize;
    syscall2(SYS_SYMLINK, oldname_ptr, newname_ptr).map(drop)
}

/// Make a new name for a file.
///
/// # Example
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-symlinkat";
/// let ret = unsafe { nc::symlinkat(oldname, nc::AT_FDCWD, newname) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn symlinkat<P: AsRef<Path>>(
    oldname: P,
    newdirfd: i32,
    newname: P,
) -> Result<(), Errno> {
    let oldname = CString::new(oldname.as_ref());
    let oldname_ptr = oldname.as_ptr() as usize;
    let newname = CString::new(newname.as_ref());
    let newname_ptr = newname.as_ptr() as usize;
    let newdirfd = newdirfd as usize;
    syscall3(SYS_SYMLINKAT, oldname_ptr, newdirfd, newname_ptr).map(drop)
}

/// Commit filesystem caches to disk.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::sync() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sync() -> Result<(), Errno> {
    syscall0(SYS_SYNC).map(drop)
}

/// Truncate a file to a specified length.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-truncate";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::truncate(path, 64 * 1024) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn truncate<P: AsRef<Path>>(filename: P, length: off_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let length = length as usize;
    syscall2(SYS_TRUNCATE, filename_ptr, length).map(drop)
}

/// Set file mode creation mask.
///
/// # Example
///
/// ```
/// let new_mask = 0o077;
/// let ret = unsafe { nc::umask(new_mask) };
/// assert!(ret.is_ok());
/// let old_mask = ret.unwrap();
/// let ret = unsafe { nc::umask(old_mask) };
/// assert_eq!(ret, Ok(new_mask));
/// ```
pub unsafe fn umask(mode: mode_t) -> Result<mode_t, Errno> {
    let mode = mode as usize;
    syscall1(SYS_UMASK, mode).map(|ret| ret as mode_t)
}

/// Delete a name and possibly the file it refers to.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-unlink";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };;
/// assert!(ret.is_ok());
/// ```
pub unsafe fn unlink<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_UNLINK, filename_ptr).map(drop)
}

/// Delete a name and possibly the file it refers to.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-unlinkat";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// // /tmp folder is not empty, so this call always returns error.
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, nc::AT_REMOVEDIR) };
/// assert!(ret.is_err());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn unlinkat<P: AsRef<Path>>(dfd: i32, filename: P, flag: i32) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flag = flag as usize;
    syscall3(SYS_UNLINKAT, dfd, filename_ptr, flag).map(drop)
}

/// Change time timestamps with nanosecond precision.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-utimesat";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let times = [
///     nc::timespec_t {
///         tv_sec: 100,
///         tv_nsec: 0,
///     },
///     nc::timespec_t {
///         tv_sec: 10,
///         tv_nsec: 0,
///     },
/// ];
/// let flags = nc::AT_SYMLINK_NOFOLLOW;
/// let ret = unsafe { nc::utimensat(nc::AT_FDCWD, path, &times, flags) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn utimensat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    times: &[timespec_t; 2],
    flags: i32,
) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let times_ptr = times.as_ptr() as usize;
    let flags = flags as usize;
    syscall4(SYS_UTIMENSAT, dirfd, filename_ptr, times_ptr, flags).map(drop)
}

/// Change file last access and modification time.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-utimes";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let times = [
///     nc::timeval_t {
///         tv_sec: 100,
///         tv_usec: 0,
///     },
///     nc::timeval_t {
///         tv_sec: 10,
///         tv_usec: 0,
///     },
/// ];
/// let ret = unsafe { nc::utimes(path, &times) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn utimes<P: AsRef<Path>>(filename: P, times: &[timeval_t; 2]) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let times_ptr = times.as_ptr() as usize;
    syscall2(SYS_UTIMES, filename_ptr, times_ptr).map(drop)
}

/// Create a child process and wait until it is terminated.
pub unsafe fn vfork() -> Result<pid_t, Errno> {
    syscall0(SYS_VFORK).map(|ret| ret as pid_t)
}

/// Wait for process to change state.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::fork() };
/// match ret {
///     Err(errno) => {
///         eprintln!("fork() error: {}", nc::strerror(errno));
///         unsafe { nc::exit(1) };
///     }
///     Ok(0) => println!("[child] pid is: {}", unsafe { nc::getpid() }),
///     Ok(pid) => {
///         let mut status = 0;
///         let mut usage = nc::rusage_t::default();
///         let ret = unsafe { nc::wait4(-1, &mut status, 0, &mut usage) };
///         assert!(ret.is_ok());
///         println!("status: {}", status);
///         let exited_pid = ret.unwrap();
///         assert_eq!(exited_pid, pid);
///     }
/// }
/// ```
pub unsafe fn wait4(
    pid: pid_t,
    wstatus: &mut i32,
    options: i32,
    rusage: &mut rusage_t,
) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    let wstatus_ptr = wstatus as *mut i32 as usize;
    let options = options as usize;
    let rusage_ptr = rusage as *mut rusage_t as usize;
    syscall4(SYS_WAIT4, pid, wstatus_ptr, options, rusage_ptr).map(|ret| ret as pid_t)
}

/// Write to a file descriptor.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-write";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let msg = "Hello, Rust!";
/// let ret = unsafe { nc::write(fd, msg.as_ptr() as usize, msg.len()) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn write(fd: i32, buf_ptr: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_WRITE, fd, buf_ptr, count).map(|ret| ret as ssize_t)
}

/// Write to a file descriptor from multiple buffers.
///
/// # Example
///
/// ```
/// use core::ffi::c_void;
///
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as *const c_void,
///     });
/// }
/// let ret = unsafe { nc::readv(fd, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
///
/// let path_out = "/tmp/nc-writev";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path_out, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::writev(fd, &iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path_out, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn writev(fd: i32, iov: &[iovec_t]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let iov_ptr = iov.as_ptr() as usize;
    let len = iov.len();
    syscall3(SYS_WRITEV, fd, iov_ptr, len).map(|ret| ret as ssize_t)
}

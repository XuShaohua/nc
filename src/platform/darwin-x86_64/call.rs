// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
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
use alloc::vec::Vec;

use crate::c_str::CString;
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

/// Accept a connection on a socket.
///
/// On success, `accept()` return a file descriptor for the accepted socket.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18082;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let mut conn_addr = nc::sockaddr_in_t::default();
///     let mut conn_addr_len: nc::socklen_t = 0;
///     let conn_fd = unsafe {
///         nc::accept(
///             listen_fd,
///             Some(&mut conn_addr as *mut nc::sockaddr_in_t as *mut nc::sockaddr_t),
///             Some(&mut conn_addr_len),
///         )?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
/// ```
pub unsafe fn accept(
    sockfd: i32,
    addr: Option<*mut sockaddr_t>,
    addrlen: Option<&mut socklen_t>,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr.map_or(core::ptr::null_mut::<sockaddr_t>() as usize, |addr| {
        addr as usize
    });
    let addrlen_ptr = addrlen.map_or(core::ptr::null_mut::<socklen_t>() as usize, |addrlen| {
        core::ptr::from_mut(addrlen) as usize
    });
    unsafe { syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr).map(|val| val as i32) }
}

/// Accept a connection on a socket.
pub unsafe fn accept_nocancel(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = core::ptr::from_mut(addr) as usize;
    let addrlen_ptr = core::ptr::from_mut(addrlen) as usize;
    unsafe { syscall3(SYS_ACCEPT_NOCANCEL, sockfd, addr_ptr, addrlen_ptr).map(|val| val as i32) }
}

/// Check user's permission for a file.
///
/// It uses the real user ID and the group access list to authorize the request.
///
/// # Examples
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
    unsafe { syscall2(SYS_ACCESS, filename_ptr, mode).map(drop) }
}

/// Switch process accounting.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-acct";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::acct(Some(path)) };
/// assert_eq!(ret, Err(nc::EPERM));
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn acct<P: AsRef<Path>>(filename: Option<P>) -> Result<(), Errno> {
    let filename = filename.map(|filename| CString::new(filename.as_ref()));
    let filename_ptr = filename.map_or(core::ptr::null::<u8>() as usize, |filename| {
        filename.as_ptr() as usize
    });
    unsafe { syscall1(SYS_ACCT, filename_ptr).map(drop) }
}

/// Correct the time to allow synchronization of the system clock.
pub unsafe fn adjtime(delta: &timeval_t, old_delta: &mut timeval_t) -> Result<(), Errno> {
    let delta_ptr = core::ptr::from_ref(delta) as usize;
    let old_delta_ptr = core::ptr::from_mut(old_delta) as usize;
    unsafe { syscall2(SYS_ADJTIME, delta_ptr, old_delta_ptr).map(drop) }
}

/// Cancel an outstanding asynchronous I/O operation (REALTIME)
pub unsafe fn aio_cancel(fd: i32, job: &mut aiocb_t) -> Result<i32, Errno> {
    let fd = fd as usize;
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall2(SYS_AIO_CANCEL, fd, job_ptr).map(|val| val as i32) }
}

/// Retrieve error status of asynchronous I/O operation
pub unsafe fn aio_error(job: &aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_ref(job) as usize;
    unsafe { syscall1(SYS_AIO_ERROR, job_ptr).map(drop) }
}

/// Asynchronous file synchronization (REALTIME)
pub unsafe fn aio_fsync(op: i32, job: &mut aiocb_t) -> Result<(), Errno> {
    let op = op as usize;
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall2(SYS_AIO_FSYNC, op, job_ptr).map(drop) }
}

/// Asynchronous read from a file (REALTIME)
pub unsafe fn aio_read(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_READ, job_ptr).map(drop) }
}

/// Retrieve return status of asynchronous I/O operation (REALTIME)
pub unsafe fn aio_return(job: &mut aiocb_t) -> Result<ssize_t, Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_RETURN, job_ptr).map(|val| val as ssize_t) }
}

/// Suspend until asynchronous I/O operations or timeout complete (REALTIME)
pub unsafe fn aio_suspend(jobs: &[aiocb_t], timeout: &timespec_t) -> Result<(), Errno> {
    let jobs_ptr = jobs.as_ptr() as usize;
    let nent = jobs.len();
    let timeout_ptr = core::ptr::from_ref(timeout) as usize;
    unsafe { syscall3(SYS_AIO_SUSPEND, jobs_ptr, nent, timeout_ptr).map(drop) }
}

/// Asynchronous write to a file (REALTIME)
pub unsafe fn aio_write(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_WRITE, job_ptr).map(drop) }
}

/// Commit BSM audit record to audit log
pub unsafe fn audit(record: &[u8]) -> Result<(), Errno> {
    let record_ptr = record.as_ptr() as usize;
    let length = record.len();
    unsafe { syscall2(SYS_AUDIT, record_ptr, length).map(drop) }
}

/// Configure system audit parameters
pub unsafe fn auditctl<P: AsRef<Path>>(path: P) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    unsafe { syscall1(SYS_AUDITCTL, path_ptr).map(drop) }
}

/// Configure system audit parameters
pub unsafe fn auditon(cmd: i32, data: &[u8]) -> Result<(), Errno> {
    let cmd = cmd as usize;
    let data_ptr = data.as_ptr() as usize;
    let length = data.len();
    unsafe { syscall3(SYS_AUDITON, cmd, data_ptr, length).map(drop) }
}

/// Bind a name to a socket.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18085;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let conn_fd = unsafe {
///         nc::accept4(
///             listen_fd,
///             None,
///             None,
///             nc::SOCK_CLOEXEC,
///         )?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
/// ```
pub unsafe fn bind(sockfd: i32, addr: *const sockaddr_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen = addrlen as usize;
    unsafe { syscall3(SYS_BIND, sockfd, addr_ptr, addrlen).map(drop) }
}

/// Change working directory.
///
/// # Examples
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let ret = unsafe { nc::chdir(path) };
/// assert!(ret.is_ok());
///
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = unsafe { nc::getcwd(&mut buf) };
/// assert!(ret.is_ok());
/// // Remove null-terminal char.
/// let path_len = ret.unwrap() as usize - 1;
/// let new_cwd = std::str::from_utf8(&buf[..path_len]);
/// assert_eq!(new_cwd, Ok(path));
/// ```
pub unsafe fn chdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    unsafe { syscall1(SYS_CHDIR, filename_ptr).map(drop) }
}

/// Set file flags.
pub unsafe fn chflags<P: AsRef<Path>>(path: P, flags: fflags_t) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_CHFLAGS, path_ptr, flags).map(drop) }
}

/// Change permissions of a file.
///
/// # Examples
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
    unsafe { syscall2(SYS_CHMOD, filename_ptr, mode).map(drop) }
}

/// Change permissions of a file.
pub unsafe fn chmod_extended<P: AsRef<Path>>(
    path: P,
    uid: uid_t,
    gid: gid_t,
    mode: i32,
    xsecurity: user_addr_t,
) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let uid = uid as usize;
    let gid = gid as usize;
    let mode = mode as usize;
    let xsecurity = xsecurity as usize;
    unsafe { syscall5(SYS_CHMOD_EXTENDED, path_ptr, uid, gid, mode, xsecurity).map(drop) }
}

/// Change ownership of a file.
///
/// # Examples
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
    unsafe { syscall3(SYS_CHOWN, filename_ptr, user, group).map(drop) }
}

/// Change the root directory.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::chroot("/") };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn chroot<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    unsafe { syscall1(SYS_CHROOT, filename_ptr).map(drop) }
}

/// Close a file descriptor.
///
/// # Examples
///
/// ```
/// const STDERR_FD: i32 = 2;
/// let ret = unsafe { nc::close(STDERR_FD) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn close(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    unsafe { syscall1(SYS_CLOSE, fd).map(drop) }
}

/// Close a file descriptor.
pub unsafe fn close_nocancel(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    unsafe { syscall1(SYS_CLOSE_NOCANCEL, fd).map(drop) }
}

/// Initialize a connection on a socket.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18081;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let mut conn_addr = nc::sockaddr_in_t::default();
///     let mut conn_addr_len: nc::socklen_t = 0;
///     let conn_fd = unsafe {
///         nc::accept4(
///             listen_fd,
///             Some(&mut conn_addr as *mut nc::sockaddr_in_t as *mut nc::sockaddr_t),
///             Some(&mut conn_addr_len),
///             nc::SOCK_CLOEXEC,
///         )?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
/// ```
pub unsafe fn connect(
    sockfd: i32,
    addr: *const sockaddr_t,
    addrlen: socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen = addrlen as usize;
    unsafe { syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen).map(drop) }
}

/// Initialize a connection on a socket.
pub unsafe fn connect_nocancel(
    sockfd: i32,
    name: caddr_t,
    addrlen: socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let name_ptr = name as usize;
    let addrlen = addrlen as usize;
    unsafe { syscall3(SYS_CONNECT_NOCANCEL, sockfd, name_ptr, addrlen).map(drop) }
}

/// Copy a file.
pub unsafe fn copyfile<P: AsRef<Path>>(from: P, to: P, mode: i32, flags: u32) -> Result<(), Errno> {
    let from = CString::new(from.as_ref());
    let from_ptr = from.as_ptr() as usize;
    let to = CString::new(to.as_ref());
    let to_ptr = to.as_ptr() as usize;
    let mode = mode as usize;
    let flags = flags as usize;
    unsafe { syscall4(SYS_COPYFILE, from_ptr, to_ptr, mode, flags).map(drop) }
}

pub unsafe fn delete(path: user_addr_t) -> Result<(), Errno> {
    let path = path as usize;
    unsafe { syscall1(SYS_DELETE, path).map(drop) }
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
///
/// # Examples
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
    unsafe { syscall1(SYS_DUP, oldfd).map(|ret| ret as i32) }
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
///
/// # Examples
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
    unsafe { syscall2(SYS_DUP2, oldfd, newfd).map(drop) }
}

/// Execute a new program.
///
/// # Examples
///
/// ```
/// let args = ["ls", "-l", "-a"];
/// let env = ["DISPLAY=:0"];
/// let ret = unsafe { nc::execve("/bin/ls", &args, &env) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn execve<P: AsRef<Path>>(filename: P, argv: &[P], env: &[P]) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;

    // Construct argument list.
    let argv_data: Vec<CString> = argv.iter().map(|arg| CString::new(arg.as_ref())).collect();
    let mut argv_data_ptr: Vec<*const u8> = argv_data.iter().map(|arg| arg.as_ptr()).collect();
    // Null-terminated
    argv_data_ptr.push(core::ptr::null::<u8>());
    let argv_ptr = argv_data_ptr.as_ptr() as usize;

    // Construct environment list.
    let env_data: Vec<CString> = env.iter().map(|item| CString::new(item.as_ref())).collect();
    let mut env_data_ptr: Vec<*const u8> = env_data.iter().map(|item| item.as_ptr()).collect();
    // Null-terminated
    env_data_ptr.push(core::ptr::null::<u8>());
    let env_ptr = env_data_ptr.as_ptr() as usize;

    unsafe { syscall3(SYS_EXECVE, filename_ptr, argv_ptr, env_ptr).map(drop) }
}

/// Terminate current process.
///
/// # Examples
///
/// ```
/// unsafe { nc::exit(0); }
/// ```
pub unsafe fn exit(status: i32) -> ! {
    let status = status as usize;
    unsafe {
        let _ret = syscall1(SYS_EXIT, status);
        core::hint::unreachable_unchecked();
    }
}

/// Check user's permission for a file.
///
/// # Examples
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
    unsafe { syscall3(SYS_FACCESSAT, dfd, filename_ptr, mode).map(drop) }
}

/// Change working directory.
///
/// # Examples
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
    unsafe { syscall1(SYS_FCHDIR, fd).map(drop) }
}

/// Set file flags.
pub unsafe fn fchflags(fd: i32, flags: fflags_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_FCHFLAGS, fd, flags).map(drop) }
}

/// Change permissions of a file.
///
/// # Examples
///
/// ```
/// let filename = "/tmp/nc-fchmod";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY,
///         0o644
///     )
/// };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let ret = unsafe { nc::fchmod(fd, 0o640) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fchmod(fd: i32, mode: mode_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let mode = mode as usize;
    unsafe { syscall2(SYS_FCHMOD, fd, mode).map(drop) }
}

/// Change permissions of a file.
///
/// # Examples
///
/// ```
/// let filename = "/tmp/nc-fchmodat";
/// let fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         filename,
///         nc::O_CREAT | nc::O_WRONLY,
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
    unsafe { syscall3(SYS_FCHMODAT, dirfd, filename_ptr, mode).map(drop) }
}

/// Change ownership of a file.
///
/// # Examples
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
    unsafe { syscall3(SYS_FCHOWN, fd, user, group).map(drop) }
}

/// Change ownership of a file.
///
/// # Examples
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
    unsafe { syscall5(SYS_FCHOWNAT, dirfd, filename_ptr, user, group, flag).map(drop) }
}

/// manipulate file descriptor.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let ret = unsafe { nc::fcntl(fd, nc::F_DUPFD, std::ptr::null()) };
/// assert!(ret.is_ok());
/// let fd2 = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd2) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fcntl(fd: i32, cmd: u32, arg: *const core::ffi::c_void) -> Result<i32, Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    let arg = arg as usize;
    unsafe { syscall3(SYS_FCNTL, fd, cmd, arg).map(|ret| ret as i32) }
}

/// Flush all modified in-core data (exclude metadata) refered by `fd` to disk.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-fdatasync";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let msg = b"Hello, Rust";
/// let ret = unsafe { nc::write(fd, msg) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fdatasync(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    unsafe { syscall1(SYS_FDATASYNC, fd).map(drop) }
}

/// Get extended attribute value.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-fgetxattr";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; 16];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::fgetxattr(fd, attr_name, &mut buf) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(attr_value.len() as nc::ssize_t));
/// let attr_len = ret.unwrap() as usize;
/// assert_eq!(attr_value.as_bytes(), &buf[..attr_len]);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fgetxattr<P: AsRef<Path>>(
    fd: i32,
    name: P,
    value: &mut [u8],
) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let value_ptr = value.as_mut_ptr() as usize;
    let size = value.len();
    unsafe { syscall4(SYS_FGETXATTR, fd, name_ptr, value_ptr, size).map(|ret| ret as ssize_t) }
}

/// Opens the file referenced by `fh` for reading and/or writing,
/// and returns the file descriptor to the calling process.
pub unsafe fn fhopen(fh: &fhandle_t, flags: i32) -> Result<i32, Errno> {
    let fh_ptr = core::ptr::from_ref(fh) as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_FHOPEN, fh_ptr, flags).map(|val| val as i32) }
}

/// List extended attribute names.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-flistxattr";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; 16];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::flistxattr(fd, &mut buf) };
/// let attr_len = ret.unwrap() as usize;
/// assert_eq!(&buf[..attr_len - 1], attr_name.as_bytes());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn flistxattr(fd: i32, value: &mut [u8]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let value_ptr = value.as_mut_ptr() as usize;
    let size = value.len();
    unsafe { syscall3(SYS_FLISTXATTR, fd, value_ptr, size).map(|ret| ret as ssize_t) }
}

/// Apply or remove an advisory lock on an open file.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-flock";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::flock(fd, nc::LOCK_EX) };
/// assert!(ret.is_ok());
/// let msg = "Hello, Rust";
/// let ret = unsafe { nc::write(fd, msg.as_bytes()) };
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
    unsafe { syscall2(SYS_FLOCK, fd, operation).map(drop) }
}

/// Mount filesystem.
pub unsafe fn fmount<P: AsRef<Path>>(
    fs_type: P,
    fd: i32,
    flags: i32,
    data: usize,
) -> Result<(), Errno> {
    let fs_type = CString::new(fs_type.as_ref());
    let fs_type_ptr = fs_type.as_ptr() as usize;
    let fd = fd as usize;
    let flags = flags as usize;
    unsafe { syscall4(SYS_FMOUNT, fs_type_ptr, fd, flags, data).map(drop) }
}

/// Create a child process.
///
/// # Examples
///
/// ```
/// let pid = unsafe { nc::fork() };
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// if pid == 0 {
///   println!("child process");
/// } else {
///   println!("parent process");
/// }
/// ```
pub unsafe fn fork() -> Result<pid_t, Errno> {
    unsafe { syscall0(SYS_FORK).map(|ret| ret as pid_t) }
}

/// Get configurable pathname variables
pub unsafe fn fpathconf(fd: i32, name: i32) -> Result<isize, Errno> {
    let fd = fd as usize;
    let name = name as usize;
    unsafe { syscall2(SYS_FPATHCONF, fd, name).map(|val| val as isize) }
}

/// Remove an extended attribute.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-fremovexattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::fremovexattr(fd, attr_name) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fremovexattr<P: AsRef<Path>>(fd: i32, name: P) -> Result<(), Errno> {
    let fd = fd as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall2(SYS_FREMOVEXATTR, fd, name_ptr).map(drop) }
}

/// Set extended attribute value.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-fsetxattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::fsetxattr(
///         fd,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fsetxattr<P: AsRef<Path>>(
    fd: i32,
    name: P,
    value: &[u8],
    flags: i32,
) -> Result<(), Errno> {
    let fd = fd as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let value_ptr = value.as_ptr() as usize;
    let size = value.len();
    let flags = flags as usize;
    unsafe { syscall5(SYS_FSETXATTR, fd, name_ptr, value_ptr, size, flags).map(drop) }
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
/// assert!(nc::S_ISDIR(stat.st_mode as nc::mode_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fstat(fd: i32, statbuf: &mut stat_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_FSTAT, fd, statbuf_ptr).map(drop) }
}

/// Get file status.
///
/// # Examples
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_PATH, 0) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut stat = nc::stat64_t::default();
/// let ret = unsafe { nc::fstat64(fd, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a directory.
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fstat64(fd: i32, statbuf: &mut stat64_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_FSTAT64, fd, statbuf_ptr).map(drop) }
}

/// Get file status.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat_t::default();
/// let ret = unsafe { nc::fstatat(nc::AT_FDCWD, path, &mut stat, nc::AT_SYMLINK_NOFOLLOW) };
/// assert!(ret.is_ok());
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
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
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    let flag = flag as usize;
    unsafe { syscall4(SYS_FSTATAT, dfd, filename_ptr, statbuf_ptr, flag).map(drop) }
}

/// Get file status.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat64_t::default();
/// let ret = unsafe { nc::fstatat64(nc::AT_FDCWD, path, &mut stat, nc::AT_SYMLINK_NOFOLLOW) };
/// assert!(ret.is_ok());
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// ```
pub unsafe fn fstatat64<P: AsRef<Path>>(
    dfd: i32,
    filename: P,
    statbuf: &mut stat64_t,
    flag: i32,
) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    let flag = flag as usize;
    unsafe { syscall4(SYS_FSTATAT64, dfd, filename_ptr, statbuf_ptr, flag).map(drop) }
}

/// Get filesystem statistics.
///
/// # Examples
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
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall2(SYS_FSTATFS, fd, buf_ptr).map(drop) }
}

/// Get filesystem statistics.
///
/// # Examples
///
/// ```
/// let path = "/usr";
/// // Open folder directly.
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_PATH, 0) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut statfs = nc::statfs64_t::default();
/// let ret = unsafe { nc::fstatfs64(fd, &mut statfs) };
/// assert!(ret.is_ok());
/// assert!(statfs.f_bfree > 0);
/// assert!(statfs.f_bavail > 0);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn fstatfs64(fd: i32, buf: &mut statfs64_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall2(SYS_FSTATFS64, fd, buf_ptr).map(drop) }
}

/// Flush all modified in-core data refered by `fd` to disk.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-fsync";
/// let fd = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY, 0o644) };
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let buf = b"Hello, Rust";
/// let n_write = unsafe { nc::write(fd, buf) };
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
    unsafe { syscall1(SYS_FSYNC, fd).map(drop) }
}

/// Flush all modified in-core data refered by `fd` to disk.
pub unsafe fn fsync_nocancel(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    unsafe { syscall1(SYS_FSYNC_NOCANCEL, fd).map(drop) }
}

/// Truncate an opened file to a specified length.
///
/// # Examples
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
    unsafe { syscall2(SYS_FTRUNCATE, fd, length).map(drop) }
}

/// Change timestamp of a file.
pub unsafe fn futimes(fd: i32, times: &[timeval_t; 2]) -> Result<(), Errno> {
    let fd = fd as usize;
    let times_ptr = times.as_ptr() as usize;
    unsafe { syscall2(SYS_FUTIMES, fd, times_ptr).map(drop) }
}

/// Retrieve audit session state
pub unsafe fn getaudit_addr(info: &mut auditinfo_addr_t, length: u32) -> Result<(), Errno> {
    let info_ptr = core::ptr::from_mut(info) as usize;
    let length = length as usize;
    unsafe { syscall2(SYS_GETAUDIT_ADDR, info_ptr, length).map(drop) }
}

/// Retrieve audit session ID
pub unsafe fn getauid(auid: &mut au_id_t) -> Result<(), Errno> {
    let auid_ptr = core::ptr::from_mut(auid) as usize;
    unsafe { syscall1(SYS_GETAUID, auid_ptr).map(drop) }
}

/// Get directory entries in a file system independent format
pub unsafe fn getdirentries(fd: i32, buf: &mut [c_char], off: off_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buf_len = buf.len();
    let off = off as usize;
    unsafe { syscall4(SYS_GETDIRENTRIES, fd, buf_ptr, buf_len, off).map(|ret| ret as ssize_t) }
}

/// Get file descriptor limit
pub unsafe fn getdtablesize() -> Result<i32, Errno> {
    unsafe { syscall0(SYS_GETDTABLESIZE).map(|val| val as i32) }
}

/// Get the effective group ID of the calling process.
///
/// # Examples
///
/// ```
/// let egid = unsafe { nc::getegid() };
/// assert!(egid > 0);
/// ```
#[must_use]
pub unsafe fn getegid() -> gid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETEGID).unwrap_or_default() as gid_t }
}

/// Get the effective user ID of the calling process.
///
/// # Examples
///
/// ```
/// let euid = unsafe { nc::geteuid() };
/// assert!(euid > 0);
/// ```
#[must_use]
pub unsafe fn geteuid() -> uid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETEUID).unwrap_or_default() as uid_t }
}

/// Get file handle.
pub unsafe fn getfh<P: AsRef<Path>>(path: P, fh: &mut fhandle_t) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let fh_ptr = core::ptr::from_mut(fh) as usize;
    unsafe { syscall2(SYS_GETFH, path_ptr, fh_ptr).map(drop) }
}

/// Get list of all mounted file systems.
///
/// If buf is None, returns number of mounted file systems.
pub unsafe fn getfsstat(buf: Option<&mut [statfs_t]>, mode: i32) -> Result<i32, Errno> {
    let buf_size = buf
        .as_ref()
        .map_or(0, |buf| buf.len() * core::mem::size_of::<statfs_t>());
    let buf_ptr = buf.map_or(core::mem::null_mut::<statfs_t>() as usize, |buf| {
        buf.as_mut_ptr() as usize
    });
    let mode = mode as usize;
    unsafe { syscall3(SYS_GETFSSTAT, buf_ptr, buf_size, mode).map(|val| val as i32) }
}

/// Get the real group ID of the calling process.
///
/// # Examples
///
/// ```
/// let gid = unsafe { nc::getgid() };
/// assert!(gid > 0);
/// ```
#[must_use]
pub unsafe fn getgid() -> gid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETGID).unwrap_or_default() as gid_t }
}

/// Get list of supplementary group Ids.
///
/// # Examples
///
/// ```
/// let mut groups = vec![];
/// let ret = unsafe { nc::getgroups(&mut groups) };
/// assert!(ret.is_ok());
/// let total_num = ret.unwrap();
/// groups.resize(total_num as usize, 0);
///
/// let ret = unsafe { nc::getgroups(&mut groups) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(total_num));
/// ```
pub unsafe fn getgroups(group_list: &mut [gid_t]) -> Result<i32, Errno> {
    let size = group_list.len();
    let group_ptr = group_list.as_mut_ptr() as usize;
    unsafe { syscall2(SYS_GETGROUPS, size, group_ptr).map(|ret| ret as i32) }
}

/// Get value of an interval timer.
///
/// # Examples
///
/// ```
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
///     let msg = b"Hello alarm\n";
///     let stderr = 2;
///     let _ = unsafe { nc::write(stderr, msg) };
/// }
///
/// let sa = nc::new_sigaction(handle_alarm);
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
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
/// let ret = unsafe { nc::setitimer(nc::ITIMER_REAL, &itv, Some(&mut prev_itv)) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);
///
/// let mask = nc::sigset_t::default();
/// let _ret = unsafe { nc::rt_sigsuspend(&mask) };
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert_eq!(prev_itv.it_value.tv_sec, 0);
/// assert_eq!(prev_itv.it_value.tv_usec, 0);
/// ```
pub unsafe fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    let which = which as usize;
    let curr_val_ptr = core::ptr::from_mut(curr_val) as usize;
    unsafe { syscall2(SYS_GETITIMER, which, curr_val_ptr).map(drop) }
}

/// Get login name.
pub unsafe fn getlogin(name: &mut [u8]) -> Result<(), Errno> {
    // TODO(Shaohua): Convert to CString
    let name_ptr = name.as_mut_ptr() as usize;
    let len = name.len();
    unsafe { syscall2(SYS_GETLOGIN, name_ptr, len).map(drop) }
}

/// Get name of connected peer socket.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18084;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let conn_fd = unsafe {
///         nc::accept4(listen_fd, None, None, nc::SOCK_CLOEXEC)?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     let mut conn_addr = nc::sockaddr_in_t::default();
///     let mut conn_addr_len: nc::socklen_t = 0;
///     unsafe {
///         let _ = nc::getpeername(conn_fd,
///             &mut conn_addr as *mut nc::sockaddr_in_t as *mut nc::sockaddr_t,
///             &mut conn_addr_len
///         );
///     }
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
pub unsafe fn getpeername(
    sockfd: i32,
    addr: *mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen_ptr = core::ptr::from_mut(addrlen) as usize;
    unsafe { syscall3(SYS_GETPEERNAME, sockfd, addr_ptr, addrlen_ptr).map(drop) }
}

/// Returns the PGID(process group ID) of the process specified by `pid`.
///
/// # Examples
///
/// ```
/// let ppid = unsafe { nc::getppid() };
/// let pgid = unsafe { nc::getpgid(ppid) };
/// assert!(pgid.is_ok());
/// ```
pub unsafe fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    unsafe { syscall1(SYS_GETPGID, pid).map(|ret| ret as pid_t) }
}

/// Get the process group ID of the calling process.
///
/// # Examples
///
/// ```
/// let pgroup = unsafe { nc::getpgrp() };
/// assert!(pgroup > 0);
/// ```
#[must_use]
pub unsafe fn getpgrp() -> pid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETPGRP).unwrap_or_default() as pid_t }
}

/// Get the process ID (PID) of the calling process.
///
/// # Examples
///
/// ```
/// let pid = unsafe { nc::getpid() };
/// assert!(pid > 0);
/// ```
#[must_use]
pub unsafe fn getpid() -> pid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETPID).unwrap_or_default() as pid_t }
}

/// Get the process ID of the parent of the calling process.
///
/// # Examples
///
/// ```
/// let ppid = unsafe { nc::getppid() };
/// assert!(ppid > 0);
/// ```
#[must_use]
pub unsafe fn getppid() -> pid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETPPID).unwrap_or_default() as pid_t }
}

/// Get program scheduling priority.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::getpriority(nc::PRIO_PROCESS, nc::getpid()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn getpriority(which: i32, who: i32) -> Result<i32, Errno> {
    let which = which as usize;
    let who = who as usize;
    unsafe {
        syscall2(SYS_GETPRIORITY, which, who).map(|ret| {
            let ret = ret as i32;
            if ret > PRIO_MAX {
                return PRIO_MAX - ret;
            }
            ret
        })
    }
}

/// Get resource limit.
///
/// # Examples
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
    let rlim_ptr = core::ptr::from_mut(rlim) as usize;
    unsafe { syscall2(SYS_GETRLIMIT, resource, rlim_ptr).map(drop) }
}

/// Get resource usage.
///
/// # Examples
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
    let usage_ptr = core::ptr::from_mut(usage) as usize;
    unsafe { syscall2(SYS_GETRUSAGE, who, usage_ptr).map(drop) }
}

/// Get session Id.
///
/// # Examples
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
    unsafe { syscall1(SYS_GETSID, pid).unwrap_or_default() as pid_t }
}

/// Get current address to which the socket `sockfd` is bound.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18088;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let conn_fd = unsafe {
///         nc::accept4(listen_fd, None, None, nc::SOCK_CLOEXEC)?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     let mut conn_addr = nc::sockaddr_in_t::default();
///     let mut conn_addr_len: nc::socklen_t = 0;
///     unsafe {
///         let _ = nc::getsockname(conn_fd,
///             &mut conn_addr as *mut nc::sockaddr_in_t as *mut nc::sockaddr_t,
///             &mut conn_addr_len
///         );
///     }
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
pub unsafe fn getsockname(
    sockfd: i32,
    addr: *mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen_ptr = core::ptr::from_mut(addrlen) as usize;
    unsafe { syscall3(SYS_GETSOCKNAME, sockfd, addr_ptr, addrlen_ptr).map(drop) }
}

/// Get options on sockets
///
/// # Examples
/// ```
/// use std::mem::size_of_val;
///
/// fn main() -> Result<(), nc::Errno> {
///     let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///
///     let set_queue_len: i32 = 5;
///     {
///         let buf_len = size_of_val(&set_queue_len) as nc::socklen_t;
///         let ret = unsafe {
///             nc::setsockopt(
///                 socket_fd,
///                 nc::IPPROTO_TCP,
///                 nc::TCP_FASTOPEN,
///                 &set_queue_len as *const i32 as *const _,
///                 buf_len,
///             )
///         };
///         assert!(ret.is_ok());
///     }
///
///     let mut get_queue_len: i32 = 0;
///     {
///         let mut buf_len = size_of_val(&get_queue_len) as nc::socklen_t;
///         let ret = unsafe {
///             nc::getsockopt(
///                 socket_fd,
///                 nc::IPPROTO_TCP,
///                 nc::TCP_FASTOPEN,
///                 &mut get_queue_len as *mut i32 as *mut _,
///                 &mut buf_len,
///             )
///         };
///         assert!(ret.is_ok());
///         println!("queue len: {get_queue_len}");
///     }
///     assert_eq!(set_queue_len, get_queue_len);
///
///     unsafe { nc::close(socket_fd) }
/// }
/// ```
pub unsafe fn getsockopt(
    sockfd: i32,
    level: i32,
    opt_name: i32,
    opt_val: *mut core::ffi::c_void,
    opt_len: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let opt_name = opt_name as usize;
    let opt_val_ptr = opt_val as usize;
    let opt_len_ptr = core::ptr::from_mut(opt_len) as usize;
    unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            sockfd,
            level,
            opt_name,
            opt_val_ptr,
            opt_len_ptr,
        )
        .map(drop)
    }
}

/// Get the caller's thread ID (TID).
///
/// # Examples
///
/// ```
/// let tid = unsafe { nc::gettid() };
/// assert!(tid > 0);
/// ```
#[must_use]
pub unsafe fn gettid() -> pid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETTID).unwrap_or_default() as pid_t }
}

/// Get time.
///
/// # Examples
///
/// ```
/// let mut tv = nc::timeval_t::default();
/// let mut tz = nc::timezone_t::default();
/// let ret = unsafe { nc::gettimeofday(&mut tv, Some(&mut tz)) };
/// assert!(ret.is_ok());
/// assert!(tv.tv_sec > 1611380386);
/// ```
pub unsafe fn gettimeofday(
    timeval: &mut timeval_t,
    tz: Option<&mut timezone_t>,
) -> Result<(), Errno> {
    let timeval_ptr = core::ptr::from_mut(timeval) as usize;
    let tz_ptr = tz.map_or(core::ptr::null_mut::<timezone_t>() as usize, |tz| {
        core::ptr::from_mut(tz) as usize
    });
    unsafe { syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop) }
}

/// Get the real user ID of the calling process.
///
/// # Examples
///
/// ```
/// let uid = unsafe { nc::getuid() };
/// assert!(uid > 0);
/// ```
#[must_use]
pub unsafe fn getuid() -> uid_t {
    // This function is always successful.
    unsafe { syscall0(SYS_GETUID).unwrap_or_default() as uid_t }
}

/// Get extended attribute value.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-getxattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; 16];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::getxattr(path, attr_name, &mut buf) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(attr_value.len() as nc::ssize_t));
/// let attr_len = ret.unwrap() as usize;
/// assert_eq!(attr_value.as_bytes(), &buf[..attr_len]);
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn getxattr<P: AsRef<Path>>(
    filename: P,
    name: P,
    value: &mut [u8],
) -> Result<ssize_t, Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let value_ptr = value.as_mut_ptr() as usize;
    let size = value.len();
    unsafe {
        syscall4(SYS_GETXATTR, filename_ptr, name_ptr, value_ptr, size).map(|ret| ret as ssize_t)
    }
}

/// Control device.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-ioctl";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut attr: i32 = 0;
/// let cmd = nc::FS_IOC_GETFLAGS;
/// let ret = unsafe { nc::ioctl(fd, cmd, &mut attr as *mut i32 as *const _) };
/// assert!(ret.is_ok());
/// println!("attr: {}", attr);
///
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn ioctl(fd: i32, cmd: u32, arg: *const core::ffi::c_void) -> Result<i32, Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    let arg = arg as usize;
    unsafe { syscall3(SYS_IOCTL, fd, cmd, arg).map(|ret| ret as i32) }
}

/// Is current process tainted by uid or gid changes
///
/// Returns 1 if the process environment or memory address space is considered “tainted”,
/// and returns 0 otherwise.
#[must_use]
pub unsafe fn issetugid() -> i32 {
    // This function is always successful.
    unsafe { syscall0(SYS_ISSETUGID).map(|val| val as i32) }.expect("issetugid() failed")
}

/// Send signal to a process.
///
/// # Examples
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
    unsafe { syscall2(SYS_KILL, pid, signal).map(drop) }
}

/// Creates a new kernel event queue and returns a descriptor.
pub unsafe fn kqueue() -> Result<i32, Errno> {
    unsafe { syscall0(SYS_KQUEUE).map(|val| val as i32) }
}

/// Change ownership of a file. Does not deference symbolic link.
///
/// # Examples
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
    unsafe { syscall3(SYS_LCHOWN, filename_ptr, user, group).map(drop) }
}

/// Make a new name for a file.
///
/// # Examples
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
    unsafe { syscall2(SYS_LINK, old_filename_ptr, new_filename_ptr).map(drop) }
}

/// Make a new name for a file.
///
/// # Examples
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
    unsafe {
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
}

/// List directed I/O (REALTIME)
pub unsafe fn lio_listio(
    mode: i32,
    acb_list: &mut [aiocb_t],
    sig: &mut sigevent_t,
) -> Result<(), Errno> {
    let mode = mode as usize;
    let acb_list_ptr = acb_list.as_mut_ptr() as usize;
    let acb_list_len = acb_list.len();
    let sig_ptr = core::ptr::from_mut(sig) as usize;
    unsafe { syscall4(SYS_LIO_LISTIO, mode, acb_list_ptr, acb_list_len, sig_ptr).map(drop) }
}

/// Listen for connections on a socket.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18086;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let conn_fd = unsafe {
///         nc::accept4(
///             listen_fd,
///             None,
///             None,
///             nc::SOCK_CLOEXEC,
///         )?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
/// ```
pub unsafe fn listen(sockfd: i32, backlog: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let backlog = backlog as usize;
    unsafe { syscall2(SYS_LISTEN, sockfd, backlog).map(drop) }
}

/// List extended attribute names.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-listxattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; 16];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::listxattr(path, &mut buf) };
/// let attr_len = ret.unwrap() as usize;
/// assert_eq!(&buf[..attr_len - 1], attr_name.as_bytes());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn listxattr<P: AsRef<Path>>(filename: P, value: &mut [u8]) -> Result<ssize_t, Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let value_ptr = value.as_mut_ptr() as usize;
    let size = value.len();
    unsafe { syscall3(SYS_LISTXATTR, filename_ptr, value_ptr, size).map(|ret| ret as ssize_t) }
}

/// Reposition file offset.
///
/// # Examples
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
    unsafe { syscall3(SYS_LSEEK, fd, offset, whence).map(drop) }
}

/// Get file status about a file, without following symbolic.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat_t::default();
/// let ret = unsafe { nc::lstat(path, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a regular file.
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// ```
pub unsafe fn lstat<P: AsRef<Path>>(filename: P, statbuf: &mut stat_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_LSTAT, filename_ptr, statbuf_ptr).map(drop) }
}

/// Get file status about a file, without following symbolic.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat64_t::default();
/// let ret = unsafe { nc::lstat64(path, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a regular file.
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// ```
pub unsafe fn lstat64<P: AsRef<Path>>(filename: P, statbuf: &mut stat64_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_LSTAT64, filename_ptr, statbuf_ptr).map(drop) }
}

/// Give advice about use of memory.
///
/// # Examples
///
/// ```
/// use std::ptr;
///
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let ret = unsafe {
///     nc::mmap(
///         ptr::null(),
///         map_length,
///         nc::PROT_READ | nc::PROT_WRITE,
///         nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
///         -1,
///         0,
///     )
/// };
/// assert!(ret.is_ok());
/// let addr = ret.unwrap();
///
/// // Notify kernel that the third page will be accessed.
/// let ret = unsafe { nc::madvise(addr.wrapping_add(2 * nc::PAGE_SIZE), nc::PAGE_SIZE, nc::MADV_WILLNEED) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn madvise(
    addr: *const core::ffi::c_void,
    len: size_t,
    advice: i32,
) -> Result<(), Errno> {
    let addr = addr as usize;
    let advice = advice as usize;
    unsafe { syscall3(SYS_MADVISE, addr, len, advice).map(drop) }
}

/// `mincore()` returns the memory residency status of the pages in the
/// current process's address space specified by `[addr, addr + len)`.
///
/// The status is returned in a vector of bytes.  The least significant
/// bit of each byte is 1 if the referenced page is in memory, otherwise
/// it is zero.
///
/// Because the status of a page can change after `mincore()` checks it
/// but before it returns to the application, the returned vector may
/// contain stale information.  Only locked pages are guaranteed to
/// remain in memory.
///
/// return values:
///  zero    - success
///  -EFAULT - vec points to an illegal address
///  -EINVAL - addr is not a multiple of `PAGE_SIZE`
///  -ENOMEM - Addresses in the range `[addr, addr + len]` are
/// invalid for the address space of this process, or specify one or
/// more pages which are not currently mapped
///  -EAGAIN - A kernel resource was temporarily unavailable.
pub unsafe fn mincore(
    start: *const core::ffi::c_void,
    len: size_t,
    vec: &mut [u8],
) -> Result<(), Errno> {
    let start = start as usize;
    let vec_ptr = vec.as_ptr() as usize;
    unsafe { syscall3(SYS_MINCORE, start, len, vec_ptr).map(drop) }
}

/// Control the inheritance of pages
pub unsafe fn minherit(addr: usize, len: size_t, inherit: i32) -> Result<(), Errno> {
    let inherit = inherit as usize;
    unsafe { syscall3(SYS_MINHERIT, addr, len, inherit).map(drop) }
}

/// Create a directory.
///
/// # Examples
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
    unsafe { syscall2(SYS_MKDIR, filename_ptr, mode).map(drop) }
}

/// Create a directory.
///
/// # Examples
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
    unsafe { syscall3(SYS_MKDIRAT, dirfd, filename_ptr, mode).map(drop) }
}

/// Create a fifo file.
pub unsafe fn mkfifo<P: AsRef<Path>>(path: P, mode: mode_t) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let mode = mode as usize;
    unsafe { syscall2(SYS_MKFIFO, path_ptr, mode).map(drop) }
}

/// Create a special or ordinary file.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-mknod";
/// // Create a named pipe.
/// let ret = unsafe { nc::mknod(path, nc::S_IFIFO | nc::S_IRUSR | nc::S_IWUSR, 0) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mknod<P: AsRef<Path>>(filename: P, mode: mode_t, dev: dev_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    let dev = dev as usize;
    unsafe { syscall3(SYS_MKNOD, filename_ptr, mode, dev).map(drop) }
}

/// Lock memory.
///
/// # Examples
///
/// ```
/// let mut passwd_buf = vec![0; 64];
/// let ret = unsafe { nc::mlock(passwd_buf.as_ptr() as *const _, passwd_buf.len()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlock(addr: *const core::ffi::c_void, len: size_t) -> Result<(), Errno> {
    let addr = addr as usize;
    unsafe { syscall2(SYS_MLOCK, addr, len).map(drop) }
}

/// Lock memory.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::mlockall(nc::MCL_CURRENT) };
/// // We got out-of-memory error in CI environment.
/// assert!(ret.is_ok() || ret == Err(nc::ENOMEM));
/// ```
pub unsafe fn mlockall(flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    unsafe { syscall1(SYS_MLOCKALL, flags).map(drop) }
}

/// Map files or devices into memory.
///
/// # Examples
///
/// ```
/// use std::{mem, ptr};
/// use std::ffi::c_void;
///
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
///         ptr::null(),
///         map_length,
///         nc::PROT_READ,
///         nc::MAP_PRIVATE,
///         fd,
///         pa_offset as nc::off_t,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr: *const c_void = addr.unwrap();
///
/// let stdout = 1;
/// // Create the "fat pointer".
/// let buf = unsafe {
///     mem::transmute::<(usize, usize), &[u8]>((addr as usize + offset - pa_offset, length))
/// };
/// let n_write = unsafe { nc::write(stdout, buf) };
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mmap(
    start: *const core::ffi::c_void,
    len: size_t,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: off_t,
) -> Result<*const core::ffi::c_void, Errno> {
    let start = start as usize;
    let prot = prot as usize;
    let flags = flags as usize;
    let fd = fd as usize;
    let offset = offset as usize;
    unsafe {
        syscall6(SYS_MMAP, start, len, prot, flags, fd, offset)
            .map(|ret| ret as *const core::ffi::c_void)
    }
}

/// Mount filesystem.
pub unsafe fn mount<P: AsRef<Path>>(
    fs_type: P,
    dir_name: P,
    flags: i32,
    data: usize,
) -> Result<(), Errno> {
    let fs_type = CString::new(fs_type.as_ref());
    let fs_type_ptr = fs_type.as_ptr() as usize;
    let dir_name = CString::new(dir_name.as_ref());
    let dir_name_ptr = dir_name.as_ptr() as usize;
    let flags = flags as usize;
    unsafe { syscall4(SYS_MOUNT, fs_type_ptr, dir_name_ptr, flags, data).map(drop) }
}

/// Set protection on a region of memory.
///
/// # Examples
///
/// ```
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let addr = unsafe {
///     nc::mmap(
///         std::ptr::null(),
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
/// let ret = unsafe { nc::mprotect(addr.wrapping_add(2 * nc::PAGE_SIZE), nc::PAGE_SIZE, nc::PROT_READ) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mprotect(
    addr: *const core::ffi::c_void,
    len: size_t,
    prot: i32,
) -> Result<(), Errno> {
    let addr = addr as usize;
    let prot = prot as usize;
    unsafe { syscall3(SYS_MPROTECT, addr, len, prot).map(drop) }
}

/// System V message control operations.
///
/// # Examples
///
/// ```
/// let key = nc::IPC_PRIVATE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
/// let ret = unsafe { nc::msgget(key, flags) };
/// assert!(ret.is_ok());
/// let msq_id = ret.unwrap();
///
/// let mut buf = nc::msqid_ds_t::default();
/// let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn msgctl(msq_id: i32, cmd: i32, buf: &mut msqid_ds_t) -> Result<i32, Errno> {
    let msq_id = msq_id as usize;
    let cmd = cmd as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall3(SYS_MSGCTL, msq_id, cmd, buf_ptr).map(|ret| ret as i32) }
}

/// Get a System V message queue identifier.
///
/// # Examples
///
/// ```
/// let key = nc::IPC_PRIVATE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | (nc::S_IRUSR | nc::S_IWUSR) as i32;
/// let ret = unsafe { nc::msgget(key, flags) };
/// assert!(ret.is_ok());
/// let msq_id = ret.unwrap();
///
/// let mut buf = nc::msqid_ds_t::default();
/// let ret = unsafe { nc::msgctl(msq_id, nc::IPC_RMID, &mut buf) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn msgget(key: key_t, msg_flag: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let msg_flag = msg_flag as usize;
    unsafe { syscall2(SYS_MSGGET, key, msg_flag).map(|ret| ret as i32) }
}

/// Receive messages from a System V message queue.
///
/// # Examples
///
/// ```
/// const MAX_MTEXT: usize = 1024;
///
/// const MTYPE_NULL: isize = 0;
/// const MTYPE_CLIENT: isize = 1;
/// const _MTYPE_SERVER: isize = 2;
///
/// #[derive(Debug, Clone, Copy)]
/// #[repr(C)]
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
///     let ret = unsafe { nc::msgsnd(msq_id, &client_msg as *const Message as *const _, msg_len, 0) };
///     assert!(ret.is_ok());
///
///     // Read from message queue.
///     let mut recv_msg = Message::default();
///     let ret = unsafe {
///         nc::msgrcv(
///             msq_id,
///             &mut recv_msg as *mut Message as *mut _,
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
    msq_id: i32,
    msgq: *mut core::ffi::c_void,
    msg_size: size_t,
    msg_type: isize,
    msg_flag: i32,
) -> Result<ssize_t, Errno> {
    let msq_id = msq_id as usize;
    let msgq = msgq as usize;
    let msg_type = msg_type as usize;
    let msg_flag = msg_flag as usize;
    unsafe {
        syscall5(SYS_MSGRCV, msq_id, msgq, msg_size, msg_type, msg_flag).map(|ret| ret as ssize_t)
    }
}

/// Append the message to a System V message queue.
///
/// # Examples
///
/// ```
/// const MAX_MTEXT: usize = 1024;
///
/// const MTYPE_NULL: isize = 0;
/// const MTYPE_CLIENT: isize = 1;
/// const _MTYPE_SERVER: isize = 2;
///
/// #[derive(Debug, Clone, Copy)]
/// #[repr(C)]
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
///     let ret = unsafe { nc::msgsnd(msq_id, &client_msg as *const Message as *const _, msg_len, 0) };
///     assert!(ret.is_ok());
///
///     // Read from message queue.
///     let mut recv_msg = Message::default();
///     let ret = unsafe {
///         nc::msgrcv(
///             msq_id,
///             &mut recv_msg as *mut Message as *mut _,
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
pub unsafe fn msgsnd(
    msq_id: i32,
    msgq: *const core::ffi::c_void,
    msg_size: size_t,
    msg_flag: i32,
) -> Result<(), Errno> {
    let msq_id = msq_id as usize;
    let msgq = msgq as usize;
    let msg_flag = msg_flag as usize;
    unsafe { syscall4(SYS_MSGSND, msq_id, msgq, msg_size, msg_flag).map(drop) }
}

pub unsafe fn msgsys(which: i32, a2: i32, a3: i32, a4: i32, a5: i32, a6: i32) -> Result<(), Errno> {
    let which = which as usize;
    let a2 = a2 as usize;
    let a3 = a3 as usize;
    let a4 = a4 as usize;
    let a5 = a5 as usize;
    let a6 = a6 as usize;
    unsafe { syscall6(SYS_MSGSYS, which, a2, a3, a4, a5, a6).map(drop) }
}

/// Synchronize a file with memory map.
pub unsafe fn msync(addr: *const core::ffi::c_void, len: size_t, flags: i32) -> Result<(), Errno> {
    let addr = addr as usize;
    let flags = flags as usize;
    unsafe { syscall3(SYS_MSYNC, addr, len, flags).map(drop) }
}

/// Unlock memory.
///
/// # Examples
///
/// ```
/// let mut passwd_buf = vec![0; 64];
/// let addr = passwd_buf.as_ptr() as *const _;
/// let ret = unsafe { nc::mlock2(addr, passwd_buf.len(), nc::MCL_CURRENT) };
/// for i in 0..passwd_buf.len() {
///   passwd_buf[i] = i as u8;
/// }
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::munlock(addr, passwd_buf.len()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlock(addr: *const core::ffi::c_void, len: size_t) -> Result<(), Errno> {
    let addr = addr as usize;
    unsafe { syscall2(SYS_MUNLOCK, addr, len).map(drop) }
}

/// Unlock memory.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::mlockall(nc::MCL_CURRENT) };
/// assert!(ret.is_ok() || ret == Err(nc::ENOMEM));
/// let ret = unsafe { nc::munlockall() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlockall() -> Result<(), Errno> {
    unsafe { syscall0(SYS_MUNLOCKALL).map(drop) }
}

/// Unmap files or devices from memory.
///
/// # Examples
///
/// ```
/// use std::{mem, ptr};
///
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
///         ptr::null(),
///         map_length,
///         nc::PROT_READ,
///         nc::MAP_PRIVATE,
///         fd,
///         pa_offset as nc::off_t,
///     )
/// };
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
/// let stdout = 1;
///
/// // Create the "fat pointer".
/// let buf = unsafe {
///     mem::transmute::<(usize, usize), &[u8]>((addr as usize + offset - pa_offset, length))
/// };
/// let n_write = unsafe { nc::write(stdout, buf) };
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// let ret = unsafe { nc::munmap(addr, map_length) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munmap(addr: *const core::ffi::c_void, len: size_t) -> Result<(), Errno> {
    let addr = addr as usize;
    unsafe { syscall2(SYS_MUNMAP, addr, len).map(drop) }
}

/// Used by the NFS daemons to pass information into and out of the kernel and
/// also to enter the kernel as a server daemon.
pub unsafe fn nfssvc(fd: i32, args: usize) -> Result<(), Errno> {
    let fd = fd as usize;
    unsafe { syscall2(SYS_NFSSVC, fd, args).map(drop) }
}

/// Used by the NTP daemon to adjust the system clock to an externally derived time.
pub unsafe fn ntp_adjtime(time: &mut timex_t) -> Result<i32, Errno> {
    let time_ptr = core::ptr::from_mut(time) as usize;
    unsafe { syscall1(SYS_NTP_ADJTIME, time_ptr).map(|val| val as i32) }
}

/// Provides the time, maximum error (sync distance) and estimated error (dispersion)
/// to client user application programs.
pub unsafe fn ntp_gettime(time: &mut ntptimeval_t) -> Result<i32, Errno> {
    let time_ptr = core::ptr::from_mut(time) as usize;
    unsafe { syscall1(SYS_NTP_GETTIME, time_ptr).map(|val| val as i32) }
}

/// Open and possibly create a file.
///
/// # Examples
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
    unsafe { syscall3(SYS_OPEN, filename_ptr, flags, mode).map(|ret| ret as i32) }
}

/// Open and possibly create a file within a directory.
///
/// # Examples
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
    unsafe { syscall4(SYS_OPENAT, dirfd, filename_ptr, flags, mode).map(|ret| ret as i32) }
}

/// Open and possibly create a file within a directory.
pub unsafe fn openat_nocancel<P: AsRef<Path>>(
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
    unsafe { syscall4(SYS_OPENAT_NOCANCEL, dirfd, filename_ptr, flags, mode).map(|ret| ret as i32) }
}

/// Get configurable pathname variables
pub unsafe fn pathconf<P: AsRef<Path>>(path: P, name: i32) -> Result<isize, Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let name = name as usize;
    unsafe { syscall2(SYS_PATHCONF, path_ptr, name).map(|val| val as isize) }
}

/// Freeze the specified process (provided in args->pid), or find and freeze a PID.
///
/// When a process is specified, this call is blocking, otherwise we wake up the
/// freezer thread and do not block on a process being frozen.
pub unsafe fn pid_hibernate(pid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    unsafe { syscall1(SYS_PID_HIBERNATE, pid).map(drop) }
}

pub unsafe fn pid_resume(pid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    unsafe { syscall1(SYS_PID_RESUME, pid).map(drop) }
}

pub unsafe fn pid_shutdown_sockets(pid: pid_t, level: i32) -> Result<(), Errno> {
    let pid = pid as usize;
    let level = level as usize;
    unsafe { syscall2(SYS_PID_SHUTDOWN_SOCKETS, pid, level).map(drop) }
}

pub unsafe fn pid_suspend(pid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    unsafe { syscall1(SYS_PID_SUSPEND, pid).map(drop) }
}

/// Create a pipe.
///
/// # Examples
///
/// ```
/// let mut fds = [-1_i32, 2];
/// let ret = unsafe { nc::pipe(&mut fds) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fds[0]) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(fds[1]) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pipe(pipefd: &mut [i32; 2]) -> Result<(), Errno> {
    let pipefd_ptr = pipefd.as_mut_ptr() as usize;
    unsafe { syscall1(SYS_PIPE, pipefd_ptr).map(drop) }
}

/// Change the root filesystem.
pub unsafe fn pivot_root<P: AsRef<Path>>(new_root: P, put_old: P) -> Result<(), Errno> {
    let new_root = CString::new(new_root.as_ref());
    let new_root_ptr = new_root.as_ptr() as usize;
    let put_old = CString::new(put_old.as_ref());
    let put_old_ptr = put_old.as_ptr() as usize;
    unsafe { syscall2(SYS_PIVOT_ROOT, new_root_ptr, put_old_ptr).map(drop) }
}

/// Wait for some event on file descriptors.
///
/// The `timeout` argument specifies the number of milliseconds that `poll()`
/// should block waiting for a file descriptor to become ready. Specifying
/// a timeout of zero causes `poll()` to return immediately, even if
/// no file descriptors are ready.
///
/// ## Return value
///
/// On success, it returns a nonnegative value which is the number of events
/// in the `fds` whose `revents` fields have been set to a nonzero value.
///
/// # Exampless
///
/// ```rust
/// use std::thread;
/// use std::time::Duration;
///
/// const STDIN_FD: i32 = 0;
/// const STDOUT_FD: i32 = 1;
///
/// fn main() {
///     let mut fds = [
///         nc::pollfd_t {
///             fd: STDIN_FD,
///             events: nc::POLLIN,
///             revents: 0,
///         },
///         nc::pollfd_t {
///             fd: STDOUT_FD,
///             events: nc::POLLOUT,
///             revents: 0,
///         },
///     ];
///
///     // Create a background thread to print some messages to stdout.
///     let handle = thread::spawn(|| {
///         thread::sleep(Duration::from_millis(100));
///         println!("MESSAGES from rust");
///     });
///
///     let ret = unsafe { nc::poll(&mut fds, 3000) };
///     assert!(ret.is_ok());
///     let num_ready = ret.unwrap();
///     println!("num of fds ready to read: {num_ready}");
///     assert!(handle.join().is_ok());
/// }
/// ```
pub unsafe fn poll(fds: &mut [pollfd_t], timeout_msecs: i32) -> Result<i32, Errno> {
    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len();
    let timeout_msecs = timeout_msecs as usize;
    unsafe { syscall3(SYS_POLL, fds_ptr, nfds, timeout_msecs).map(|ret| ret as i32) }
}

/// Read from a file descriptor without changing file offset.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let read_count = 64;
/// let mut buf = [0_u8; 128];
/// let ret = unsafe { nc::pread(fd, &mut buf[..read_count], 0) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(read_count as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pread(fd: i32, buf: &mut [u8], offset: off_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let count = buf.len();
    let offset = offset as usize;
    unsafe { syscall4(SYS_PREAD, fd, buf_ptr, count, offset).map(|ret| ret as ssize_t) }
}

/// Read from a file descriptor without changing file offset.
///
/// # Examples
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
/// let ret = unsafe { nc::preadv(fd as usize, &mut iov, 0, iov_len - 1) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn preadv(
    fd: usize,
    vec: &mut [iovec_t],
    pos_l: usize,
    pos_h: usize,
) -> Result<ssize_t, Errno> {
    let vec_ptr = vec.as_mut_ptr() as usize;
    let vec_len = vec.len();
    unsafe { syscall5(SYS_PREADV, fd, vec_ptr, vec_len, pos_l, pos_h).map(|ret| ret as ssize_t) }
}

/// Process trace.
pub unsafe fn ptrace(request: i32, pid: pid_t, addr: usize, data: usize) -> Result<isize, Errno> {
    let request = request as usize;
    let pid = pid as usize;
    unsafe { syscall4(SYS_PTRACE, request, pid, addr, data).map(|ret| ret as isize) }
}

/// Write to a file descriptor without changing file offset.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-pwrite64";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let msg = "Hello, Rust";
/// let ret = unsafe { nc::pwrite64(fd, msg.as_bytes(), 0) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pwrite(fd: i32, buf: &[u8], offset: off_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let count = buf.len();
    let offset = offset as usize;
    unsafe { syscall4(SYS_PWRITE, fd, buf_ptr, count, offset).map(|ret| ret as ssize_t) }
}

/// Write to a file descriptor without changing file offset.
///
/// # Examples
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
/// let ret = unsafe { nc::readv(fd as usize, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
///
/// let path_out = "/tmp/nc-pwritev";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path_out, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::pwritev(fd as usize, &iov, 0, iov.len() - 1) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path_out, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pwritev(
    fd: usize,
    vec: &[iovec_t],
    pos_l: usize,
    pos_h: usize,
) -> Result<ssize_t, Errno> {
    let vec_ptr = vec.as_ptr() as usize;
    let vec_len = vec.len();
    unsafe { syscall5(SYS_PWRITEV, fd, vec_ptr, vec_len, pos_l, pos_h).map(|ret| ret as ssize_t) }
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
    unsafe { syscall4(SYS_QUOTACTL, path_ptr, cmd, id, addr).map(drop) }
}

/// Read from a file descriptor.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [0_u8; 4 * 1024];
/// let ret = unsafe { nc::read(fd, &mut buf) };
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap();
/// assert!(n_read <= buf.len() as nc::ssize_t);
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn read(fd: i32, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let count = buf.len();
    unsafe { syscall3(SYS_READ, fd, buf_ptr, count).map(|ret| ret as ssize_t) }
}

/// Read value of a symbolic link.
///
/// # Examples
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlink";
/// let ret = unsafe { nc::symlinkat(oldname, nc::AT_FDCWD, newname) };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = unsafe { nc::readlink(newname, &mut buf) };
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap() as usize;
/// assert_eq!(n_read, oldname.len());
/// assert_eq!(oldname.as_bytes(), &buf[0..n_read]);
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn readlink<P: AsRef<Path>>(filename: P, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buf_len = buf.len();
    unsafe { syscall3(SYS_READLINK, filename_ptr, buf_ptr, buf_len).map(|ret| ret as ssize_t) }
}

/// Read value of a symbolic link.
///
/// # Examples
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlinkat";
/// let ret = unsafe { nc::symlinkat(oldname, nc::AT_FDCWD, newname) };
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let buf_len = buf.len();
/// let ret = unsafe { nc::readlinkat(nc::AT_FDCWD, newname, &mut buf) };
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
) -> Result<ssize_t, Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buf_len = buf.len();
    unsafe {
        syscall4(SYS_READLINKAT, dirfd, filename_ptr, buf_ptr, buf_len).map(|ret| ret as ssize_t)
    }
}

/// Read from a file descriptor into multiple buffers.
///
/// # Examples
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
///         iov_base: item.as_ptr() as *const c_void,
///         iov_len: item.len(),
///     });
/// }
/// let ret = unsafe { nc::readv(fd as usize, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn readv(fd: usize, iov: &mut [iovec_t]) -> Result<ssize_t, Errno> {
    let iov_ptr = iov.as_mut_ptr() as usize;
    let len = iov.len();
    unsafe { syscall3(SYS_READV, fd, iov_ptr, len).map(|ret| ret as ssize_t) }
}

/// Reboot or enable/disable Ctrl-Alt-Del.
///
/// # Examples
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
    unsafe { syscall4(SYS_REBOOT, magic, magic2, cmd, arg).map(drop) }
}

/// Receive a message from a socket.
///
/// # Examples
///
/// ```
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// fn main() {
///     let mut fds = [-1_i32; 2];
///
///     let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
///     assert!(ret.is_ok());
///     println!("socket pairs: {}, {}", fds[0], fds[1]);
///
///     // Start worker thread
///     thread::spawn(move || {
///         println!("worker thread started");
///         let msg = "Hello, Rust";
///         println!("[worker] Will send msg: {msg}");
///         let ret = unsafe { nc::sendto(fds[WRITE_SIDE], msg.as_bytes(), 0, None, 0) };
///         assert!(ret.is_ok());
///         assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
///     });
///
///     let mut buf = [0_u8; 1024];
///     let ret = unsafe { nc::recvfrom(fds[READ_SIDE], &mut buf, 0, None, None) };
///     assert!(ret.is_ok());
///     let nread = ret.unwrap();
///     let msg = std::str::from_utf8(&buf[..nread as usize]).unwrap();
///     println!("[main] recv msg: {msg}");
///
///     unsafe {
///         let _ = nc::close(fds[0]);
///         let _ = nc::close(fds[1]);
///     }
/// }
/// ```
pub unsafe fn recvfrom(
    sockfd: i32,
    buf: &mut [u8],
    flags: i32,
    src_addr: Option<*mut sockaddr_t>,
    addrlen: Option<&mut socklen_t>,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buflen = buf.len();
    let flags = flags as usize;
    let src_addr_ptr = src_addr.map_or(core::ptr::null_mut::<sockaddr_t>() as usize, |src_addr| {
        src_addr as usize
    });
    let addrlen_ptr = addrlen.map_or(core::ptr::null_mut::<socklen_t>() as usize, |addrlen| {
        core::ptr::from_mut(addrlen) as usize
    });
    unsafe {
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
}

/// Receive a msg from a socket.
///
/// # Examples
///
/// ```
/// use std::ffi::c_void;
/// use std::ptr;
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// fn main() {
///     let mut fds = [-1_i32; 2];
///
///     let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
///     assert!(ret.is_ok());
///     println!("socket pairs: {}, {}", fds[0], fds[1]);
///
///     // Start worker thread
///     thread::spawn(move || {
///         println!("worker thread started");
///         let msg = "Hello, Rust";
///         println!("[worker] Will send msg: {msg}");
///         let mut iov = [nc::iovec_t {
///             iov_base: msg.as_ptr() as *const c_void,
///             iov_len: msg.len(),
///         }];
///         let msg_hdr = nc::msghdr_t {
///             msg_name: ptr::null(),
///             msg_namelen: 0,
///             msg_iov: iov.as_mut_ptr(),
///             msg_iovlen: iov.len(),
///             msg_control: ptr::null(),
///             msg_controllen: 0,
///             msg_flags: 0,
///         };
///         let ret = unsafe { nc::sendmsg(fds[WRITE_SIDE], &msg_hdr, 0) };
///         assert!(ret.is_ok());
///         assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
///     });
///
///     let mut buf = [[0_u8; 64]; 4];
///     let mut iov = Vec::with_capacity(buf.len());
///     for ref mut item in (&mut buf).iter() {
///         iov.push(nc::iovec_t {
///             iov_base: item.as_ptr() as *const c_void,
///             iov_len: item.len(),
///         });
///     }
///     let mut msg_hdr = nc::msghdr_t {
///         msg_name: ptr::null(),
///         msg_namelen: 0,
///         msg_iov: iov.as_mut_ptr(),
///         msg_iovlen: iov.len(),
///         msg_control: ptr::null(),
///         msg_controllen: 0,
///         msg_flags: 0,
///     };
///     let ret = unsafe { nc::recvmsg(fds[READ_SIDE], &mut msg_hdr, 0) };
///     assert!(ret.is_ok());
///     let nread = ret.unwrap();
///     // We only read the first buffer block.
///     let msg = std::str::from_utf8(&buf[0][..nread as usize]).unwrap();
///     println!("[main] recv msg: {msg}");
///
///     unsafe {
///         let _ = nc::close(fds[0]);
///         let _ = nc::close(fds[1]);
///     }
/// }
/// ```
pub unsafe fn recvmsg(sockfd: i32, msg: &mut msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = core::ptr::from_mut(msg) as usize;
    let flags = flags as usize;
    unsafe { syscall3(SYS_RECVMSG, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t) }
}

/// Remove an extended attribute.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-removexattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::removexattr(path, attr_name) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn removexattr<P: AsRef<Path>>(filename: P, name: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall2(SYS_REMOVEXATTR, filename_ptr, name_ptr).map(drop) }
}

/// Change name or location of a file.
///
/// # Examples
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
    unsafe { syscall2(SYS_RENAME, oldfilename_ptr, newfilename_ptr).map(drop) }
}

/// Change name or location of a file.
///
/// # Examples
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
    unsafe {
        syscall4(
            SYS_RENAMEAT,
            olddfd,
            oldfilename_ptr,
            newdfd,
            newfilename_ptr,
        )
        .map(drop)
    }
}

/// Revoke file access
pub unsafe fn revoke<P: AsRef<Path>>(path: P) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    unsafe { syscall1(SYS_REVOKE, path_ptr).map(drop) }
}

/// Delete a directory.
///
/// # Examples
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
    unsafe { syscall1(SYS_RMDIR, filename_ptr).map(drop) }
}

/// Sychronous I/O multiplexing.
pub unsafe fn select(
    nfds: i32,
    read_fds: Option<&mut fd_set_t>,
    write_fds: Option<&mut fd_set_t>,
    except_fds: Option<&mut fd_set_t>,
    timeout: Option<&timeval_t>,
) -> Result<i32, Errno> {
    use core::ptr::{null, null_mut};

    let nfds = nfds as usize;
    let read_fds_ptr = read_fds.map_or(null_mut::<fd_set_t>() as usize, |read_fds| {
        core::ptr::from_mut(read_fds) as usize
    });
    let write_fds_ptr = write_fds.map_or(null_mut::<fd_set_t>() as usize, |write_fds| {
        core::ptr::from_mut(write_fds) as usize
    });
    let except_fds_ptr = except_fds.map_or(null_mut::<fd_set_t>() as usize, |except_fds| {
        core::ptr::from_mut(except_fds) as usize
    });
    let timeout_ptr = timeout.map_or(null::<timeval_t>() as usize, |timeout| {
        core::ptr::from_ref(timeout) as usize
    });
    unsafe {
        syscall5(
            SYS_SELECT,
            nfds,
            read_fds_ptr,
            write_fds_ptr,
            except_fds_ptr,
            timeout_ptr,
        )
        .map(|ret| ret as i32)
    }
}

/// Sychronous I/O multiplexing.
pub unsafe fn select_nocancel(
    nfds: i32,
    readfds: *mut u32,
    writefds: *mut u32,
    exceptfds: *mut u32,
    timeout: &mut timeval_t,
) -> Result<i32, Errno> {
    let nfds = nfds as usize;
    let readfds_ptr = readfds as usize;
    let writefds_ptr = writefds as usize;
    let exceptfds_ptr = exceptfds as usize;
    let timeout_ptr = core::ptr::from_mut(timeout) as usize;
    unsafe {
        syscall5(
            SYS_SELECT_NOCANCEL,
            nfds,
            readfds_ptr,
            writefds_ptr,
            exceptfds_ptr,
            timeout_ptr,
        )
        .map(|ret| ret as i32)
    }
}

/// System V semaphore control operations
///
/// # Examples
///
/// ```
/// use std::thread;
/// use std::time::Duration;
///
/// pub struct BinarySemaphore {
///     key: i32,
///     semid: i32,
///     is_producer: bool,
/// }
///
/// impl BinarySemaphore {
///     const SEM_NUM: i32 = 0;
///     const FIRST_SEM: u16 = 0;
///     const SEM_MAX_VAL: i32 = 1;
///     const SEM_OP_RESERVE: i16 = -1;
///     const SEM_OP_RELEASE: i16 = 1;
///
///     pub fn new(key: i32, is_producer: bool) -> Result<Self, nc::Errno> {
///         let semid =
///             unsafe { nc::semget(key, 1, nc::IPC_CREAT | (nc::S_IRUSR | nc::S_IWUSR) as i32)? };
///
///         let ret = unsafe {
///             let arg = Self::SEM_MAX_VAL as usize;
///             nc::semctl(semid, Self::SEM_NUM, nc::SETVAL, arg)
///         };
///
///         if let Err(errno) = ret {
///             let _ret = unsafe { nc::semctl(semid, nc::IPC_RMID, 0, 0) };
///             return Err(errno);
///         }
///
///         Ok(Self {
///             key,
///             semid,
///             is_producer,
///         })
///     }
///
///     pub fn reserve(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RESERVE,
///             sem_flg: 0,
///         }];
///
///         loop {
///             let ret = unsafe { nc::semop(self.semid, &mut ops) };
///             match ret {
///                 Ok(_) => return Ok(()),
///                 Err(nc::EINTR) => continue,
///                 Err(errno) => return Err(errno),
///             }
///         }
///     }
///
///     pub fn release(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RELEASE,
///             sem_flg: 0,
///         }];
///         unsafe { nc::semop(self.semid, &mut ops) }
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn key(&self) -> i32 {
///         self.key
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn is_producer(&self) -> bool {
///         self.is_producer
///     }
/// }
///
/// impl Drop for BinarySemaphore {
///     fn drop(&mut self) {
///         if self.is_producer {
///             let ret = unsafe { nc::semctl(self.semid, nc::IPC_RMID, 0, 0) };
///             assert!(ret.is_ok());
///         }
///     }
/// }
///
/// const KEY_ID: i32 = 0x1234;
/// let ret = BinarySemaphore::new(KEY_ID, true);
/// if let Err(errno) = ret {
///     eprintln!("sem init failed: {}", nc::strerror(errno));
///     return;
/// }
/// let mut sem = ret.unwrap();
///
/// // child thread as consumer
/// let handle = thread::spawn(|| {
///     let mut sem = BinarySemaphore::new(KEY_ID, false).unwrap();
///     for _ in 0..5 {
///         if let Err(errno) = sem.reserve() {
///             eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///             break;
///         }
///         println!("[worker] wait for 100 millis");
///         thread::sleep(Duration::from_millis(100));
///         if let Err(errno) = sem.release() {
///             eprintln!("[worker] sem release failed: {}", nc::strerror(errno));
///         }
///     }
/// });
///
/// // parent thread as producer
/// for _ in 0..5 {
///     if let Err(errno) = sem.reserve() {
///         eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///         break;
///     }
///     println!("[main] wait for 200 millis");
///     thread::sleep(Duration::from_millis(200));
///     if let Err(errno) = sem.release() {
///         eprintln!("[main] sem release failed: {}", nc::strerror(errno));
///     }
/// }
///
/// let _ = handle.join();
/// ```
pub unsafe fn semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
    let semid = semid as usize;
    let semnum = semnum as usize;
    let cmd = cmd as usize;
    unsafe { syscall4(SYS_SEMCTL, semid, semnum, cmd, arg).map(|ret| ret as i32) }
}

/// Get a System V semphore set identifier.
///
/// # Examples
///
/// ```
/// use std::thread;
/// use std::time::Duration;
///
/// pub struct BinarySemaphore {
///     key: i32,
///     semid: i32,
///     is_producer: bool,
/// }
///
/// impl BinarySemaphore {
///     const SEM_NUM: i32 = 0;
///     const FIRST_SEM: u16 = 0;
///     const SEM_MAX_VAL: i32 = 1;
///     const SEM_OP_RESERVE: i16 = -1;
///     const SEM_OP_RELEASE: i16 = 1;
///
///     pub fn new(key: i32, is_producer: bool) -> Result<Self, nc::Errno> {
///         let semid =
///             unsafe { nc::semget(key, 1, nc::IPC_CREAT | (nc::S_IRUSR | nc::S_IWUSR) as i32)? };
///
///         let ret = unsafe {
///             let arg = Self::SEM_MAX_VAL as usize;
///             nc::semctl(semid, Self::SEM_NUM, nc::SETVAL, arg)
///         };
///
///         if let Err(errno) = ret {
///             let _ret = unsafe { nc::semctl(semid, nc::IPC_RMID, 0, 0) };
///             return Err(errno);
///         }
///
///         Ok(Self {
///             key,
///             semid,
///             is_producer,
///         })
///     }
///
///     pub fn reserve(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RESERVE,
///             sem_flg: 0,
///         }];
///
///         loop {
///             let ret = unsafe { nc::semop(self.semid, &mut ops) };
///             match ret {
///                 Ok(_) => return Ok(()),
///                 Err(nc::EINTR) => continue,
///                 Err(errno) => return Err(errno),
///             }
///         }
///     }
///
///     pub fn release(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RELEASE,
///             sem_flg: 0,
///         }];
///         unsafe { nc::semop(self.semid, &mut ops) }
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn key(&self) -> i32 {
///         self.key
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn is_producer(&self) -> bool {
///         self.is_producer
///     }
/// }
///
/// impl Drop for BinarySemaphore {
///     fn drop(&mut self) {
///         if self.is_producer {
///             let ret = unsafe { nc::semctl(self.semid, nc::IPC_RMID, 0, 0) };
///             assert!(ret.is_ok());
///         }
///     }
/// }
///
/// const KEY_ID: i32 = 0x1235;
/// let ret = BinarySemaphore::new(KEY_ID, true);
/// if let Err(errno) = ret {
///     eprintln!("sem init failed: {}", nc::strerror(errno));
///     return;
/// }
/// let mut sem = ret.unwrap();
///
/// // child thread as consumer
/// let handle = thread::spawn(|| {
///     let mut sem = BinarySemaphore::new(KEY_ID, false).unwrap();
///     for _ in 0..5 {
///         if let Err(errno) = sem.reserve() {
///             eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///             break;
///         }
///         println!("[worker] wait for 100 millis");
///         thread::sleep(Duration::from_millis(100));
///         if let Err(errno) = sem.release() {
///             eprintln!("[worker] sem release failed: {}", nc::strerror(errno));
///         }
///     }
/// });
///
/// // parent thread as producer
/// for _ in 0..5 {
///     if let Err(errno) = sem.reserve() {
///         eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///         break;
///     }
///     println!("[main] wait for 200 millis");
///     thread::sleep(Duration::from_millis(200));
///     if let Err(errno) = sem.release() {
///         eprintln!("[main] sem release failed: {}", nc::strerror(errno));
///     }
/// }
///
/// let _ = handle.join();
/// ```
pub unsafe fn semget(key: key_t, nsems: i32, sem_flag: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let nsems = nsems as usize;
    let sem_flag = sem_flag as usize;
    unsafe { syscall3(SYS_SEMGET, key, nsems, sem_flag).map(|ret| ret as i32) }
}

/// System V semphore operations.
///
/// # Examples
///
/// ```
/// use std::thread;
/// use std::time::Duration;
///
/// pub struct BinarySemaphore {
///     key: i32,
///     semid: i32,
///     is_producer: bool,
/// }
///
/// impl BinarySemaphore {
///     const SEM_NUM: i32 = 0;
///     const FIRST_SEM: u16 = 0;
///     const SEM_MAX_VAL: i32 = 1;
///     const SEM_OP_RESERVE: i16 = -1;
///     const SEM_OP_RELEASE: i16 = 1;
///
///     pub fn new(key: i32, is_producer: bool) -> Result<Self, nc::Errno> {
///         let semid =
///             unsafe { nc::semget(key, 1, nc::IPC_CREAT | (nc::S_IRUSR | nc::S_IWUSR) as i32)? };
///
///         let ret = unsafe {
///             let arg = Self::SEM_MAX_VAL as usize;
///             nc::semctl(semid, Self::SEM_NUM, nc::SETVAL, arg)
///         };
///
///         if let Err(errno) = ret {
///             let _ret = unsafe { nc::semctl(semid, nc::IPC_RMID, 0, 0) };
///             return Err(errno);
///         }
///
///         Ok(Self {
///             key,
///             semid,
///             is_producer,
///         })
///     }
///
///     pub fn reserve(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RESERVE,
///             sem_flg: 0,
///         }];
///
///         loop {
///             let ret = unsafe { nc::semop(self.semid, &mut ops) };
///             match ret {
///                 Ok(_) => return Ok(()),
///                 Err(nc::EINTR) => continue,
///                 Err(errno) => return Err(errno),
///             }
///         }
///     }
///
///     pub fn release(&mut self) -> Result<(), nc::Errno> {
///         let mut ops = [nc::sembuf_t {
///             sem_num: Self::FIRST_SEM,
///             sem_op: Self::SEM_OP_RELEASE,
///             sem_flg: 0,
///         }];
///         unsafe { nc::semop(self.semid, &mut ops) }
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn key(&self) -> i32 {
///         self.key
///     }
///
///     #[must_use]
///     #[inline]
///     pub const fn is_producer(&self) -> bool {
///         self.is_producer
///     }
/// }
///
/// impl Drop for BinarySemaphore {
///     fn drop(&mut self) {
///         if self.is_producer {
///             let ret = unsafe { nc::semctl(self.semid, nc::IPC_RMID, 0, 0) };
///             assert!(ret.is_ok());
///         }
///     }
/// }
///
/// const KEY_ID: i32 = 0x1236;
/// let ret = BinarySemaphore::new(KEY_ID, true);
/// if let Err(errno) = ret {
///     eprintln!("sem init failed: {}", nc::strerror(errno));
///     return;
/// }
/// let mut sem = ret.unwrap();
///
/// // child thread as consumer
/// let handle = thread::spawn(|| {
///     let mut sem = BinarySemaphore::new(KEY_ID, false).unwrap();
///     for _ in 0..5 {
///         if let Err(errno) = sem.reserve() {
///             eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///             break;
///         }
///         println!("[worker] wait for 100 millis");
///         thread::sleep(Duration::from_millis(100));
///         if let Err(errno) = sem.release() {
///             eprintln!("[worker] sem release failed: {}", nc::strerror(errno));
///         }
///     }
/// });
///
/// // parent thread as producer
/// for _ in 0..5 {
///     if let Err(errno) = sem.reserve() {
///         eprintln!("[worker ]sem reserve failed: {}", nc::strerror(errno));
///         break;
///     }
///     println!("[main] wait for 200 millis");
///     thread::sleep(Duration::from_millis(200));
///     if let Err(errno) = sem.release() {
///         eprintln!("[main] sem release failed: {}", nc::strerror(errno));
///     }
/// }
///
/// let _ = handle.join();
/// ```
pub unsafe fn semop(semid: i32, sops: &mut [sembuf_t]) -> Result<(), Errno> {
    let semid = semid as usize;
    let sops_ptr = sops.as_mut_ptr() as usize;
    let nops = sops.len();
    unsafe { syscall3(SYS_SEMOP, semid, sops_ptr, nops).map(drop) }
}

pub unsafe fn semsys(which: i32, a2: i32, a3: i32, a4: i32, a5: i32) -> Result<(), Errno> {
    let which = which as usize;
    let a2 = a2 as usize;
    let a3 = a3 as usize;
    let a4 = a4 as usize;
    let a5 = a5 as usize;
    unsafe { syscall5(SYS_SEMSYS, which, a2, a3, a4, a5).map(drop) }
}

/// Close an semaphore.
pub unsafe fn sem_close(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_CLOSE, sem_ptr).map(drop) }
}

/// Creates or opens the named semaphore specified by `name`.
pub unsafe fn sem_open<P: AsRef<Path>>(
    name: P,
    flags: i32,
    mode: mode_t,
    value: u32,
) -> Result<user_addr_t, Errno> {
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    let value = value as usize;
    unsafe { syscall4(SYS_SEM_OPEN, name_ptr, flags, mode, value).map(|ret| ret as user_addr_t) }
}

/// Increment (unlock) a semaphore.
pub unsafe fn sem_post(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_POST, sem_ptr).map(drop) }
}

/// Decrement (lock) a semaphore.
pub unsafe fn sem_trywait(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_TRYWAIT, sem_ptr).map(drop) }
}

/// Remove an semaphore.
pub unsafe fn sem_unlink<P: AsRef<Path>>(name: P) -> Result<(), Errno> {
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall1(SYS_SEM_UNLINK, name_ptr).map(drop) }
}

/// Decrement (lock) a semaphore.
pub unsafe fn sem_wait(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_WAIT, sem_ptr).map(drop) }
}

/// Decrement (lock) a semaphore.
pub unsafe fn sem_wait_nocancel(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_WAIT_NOCANCEL, sem_ptr).map(drop) }
}

/// Transfer data between two file descriptors.
///
/// # Examples
///
/// ```
/// println!("S_IRUSR: {}", nc::S_IRUSR);
/// println!("S_IRGRP: {}", nc::S_IRGRP);
///
/// let in_filename = "/etc/passwd";
/// let out_filename = "/tmp/passwd.copy";
///
/// #[cfg(any(target_os = "linux", target_os = "android"))]
/// let in_fd = unsafe {
///     nc::openat(nc::AT_FDCWD, in_filename, nc::O_RDONLY, 0).expect("Failed to open file!")
/// };
///
/// #[cfg(target_os = "freebsd")]
/// let in_fd = unsafe {
///     nc::openat(nc::AT_FDCWD, in_filename, nc::O_RDONLY, 0).expect("Failed to open file!")
/// };
///
/// #[cfg(any(target_os = "linux", target_os = "android"))]
/// let out_fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         out_filename,
///         nc::O_WRONLY | nc::O_CREAT,
///         nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
///     )
///     .expect("Failed to open passwd copy file")
/// };
///
/// #[cfg(target_os = "freebsd")]
/// let out_fd = unsafe {
///     nc::openat(
///         nc::AT_FDCWD,
///         out_filename,
///         nc::O_WRONLY | nc::O_CREAT,
///         nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
///     )
///     .expect("Failed to open passwd copy file")
/// };
///
/// let mut stat = nc::stat_t::default();
/// unsafe { nc::fstat(in_fd, &mut stat).expect("Failed to get file stat!") };
/// println!("stat: {:?}", stat);
///
/// let count = stat.st_blksize as usize;
/// println!("count: {}", count);
/// let nread =
///     unsafe { nc::sendfile(out_fd, in_fd, None, count).expect("Failed to call sendfile()") };
/// println!("nread: {}", nread);
///
/// unsafe {
///     let _ = nc::close(in_fd);
///     let _ = nc::close(out_fd);
/// }
///
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, out_filename, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sendfile(
    out_fd: i32,
    in_fd: i32,
    offset: Option<&mut off_t>,
    count: size_t,
) -> Result<ssize_t, Errno> {
    let out_fd = out_fd as usize;
    let in_fd = in_fd as usize;
    let offset_ptr = offset.map_or(core::ptr::null_mut::<off_t>() as usize, |offset| {
        core::ptr::from_mut(offset) as usize
    });
    unsafe { syscall4(SYS_SENDFILE, out_fd, in_fd, offset_ptr, count).map(|ret| ret as ssize_t) }
}

/// Send a message on a socket.
///
/// Allow sending ancillary data.
///
/// # Examples
///
/// ```
/// use std::ffi::c_void;
/// use std::ptr;
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// fn main() {
///     let mut fds = [-1_i32; 2];
///
///     let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
///     assert!(ret.is_ok());
///     println!("socket pairs: {}, {}", fds[0], fds[1]);
///
///     // Start worker thread
///     thread::spawn(move || {
///         println!("worker thread started");
///         let msg = "Hello, Rust";
///         println!("[worker] Will send msg: {msg}");
///         let mut iov = [nc::iovec_t {
///             iov_base: msg.as_ptr() as *const c_void,
///             iov_len: msg.len(),
///         }];
///         let msg_hdr = nc::msghdr_t {
///             msg_name: ptr::null(),
///             msg_namelen: 0,
///             msg_iov: iov.as_mut_ptr(),
///             msg_iovlen: iov.len(),
///             msg_control: ptr::null(),
///             msg_controllen: 0,
///             msg_flags: 0,
///         };
///         let ret = unsafe { nc::sendmsg(fds[WRITE_SIDE], &msg_hdr, 0) };
///         assert!(ret.is_ok());
///         assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
///     });
///
///     let mut buf = [[0_u8; 64]; 4];
///     let mut iov = Vec::with_capacity(buf.len());
///     for ref mut item in (&mut buf).iter() {
///         iov.push(nc::iovec_t {
///             iov_base: item.as_ptr() as *const c_void,
///             iov_len: item.len(),
///         });
///     }
///     let mut msg_hdr = nc::msghdr_t {
///         msg_name: ptr::null(),
///         msg_namelen: 0,
///         msg_iov: iov.as_mut_ptr(),
///         msg_iovlen: iov.len(),
///         msg_control: ptr::null(),
///         msg_controllen: 0,
///         msg_flags: 0,
///     };
///     let ret = unsafe { nc::recvmsg(fds[READ_SIDE], &mut msg_hdr, 0) };
///     assert!(ret.is_ok());
///     let nread = ret.unwrap();
///     // We only read the first buffer block.
///     let msg = std::str::from_utf8(&buf[0][..nread as usize]).unwrap();
///     println!("[main] recv msg: {msg}");
///
///     unsafe {
///         let _ = nc::close(fds[0]);
///         let _ = nc::close(fds[1]);
///     }
/// }
/// ```
pub unsafe fn sendmsg(sockfd: i32, msg: &msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = core::ptr::from_ref(msg) as usize;
    let flags = flags as usize;
    unsafe { syscall3(SYS_SENDMSG, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t) }
}

/// Send a message on a socket. Allow sending ancillary data.
pub unsafe fn sendmsg_nocancel(sockfd: i32, msg: caddr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = msg as usize;
    let flags = flags as usize;
    unsafe { syscall3(SYS_SENDMSG_NOCANCEL, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t) }
}

/// Send a message on a socket.
///
/// # Examples
///
/// ```
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// fn main() {
///     let mut fds = [-1_i32; 2];
///
///     let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
///     assert!(ret.is_ok());
///     println!("socket pairs: {}, {}", fds[0], fds[1]);
///
///     // Start worker thread
///     thread::spawn(move || {
///         println!("worker thread started");
///         let msg = "Hello, Rust";
///         println!("[worker] Will send msg: {msg}");
///         let ret = unsafe { nc::sendto(fds[WRITE_SIDE], msg.as_bytes(), 0, None, 0) };
///         assert!(ret.is_ok());
///         assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
///     });
///
///     let mut buf = [0_u8; 1024];
///     let ret = unsafe { nc::recvfrom(fds[READ_SIDE], &mut buf, 0, None, None) };
///     assert!(ret.is_ok());
///     let nread = ret.unwrap();
///     let msg = std::str::from_utf8(&buf[..nread as usize]).unwrap();
///     println!("[main] recv msg: {msg}");
///
///     unsafe {
///         let _ = nc::close(fds[0]);
///         let _ = nc::close(fds[1]);
///     }
/// }
/// ```
pub unsafe fn sendto(
    sockfd: i32,
    buf: &[u8],
    flags: i32,
    dest_addr: Option<*const sockaddr_t>,
    addrlen: socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let len = buf.len();
    let flags = flags as usize;
    let dest_addr_ptr = dest_addr.map_or(core::ptr::null::<sockaddr_t>() as usize, |dest_addr| {
        dest_addr as usize
    });
    let addrlen = addrlen as usize;
    unsafe {
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
}

/// Send a message on a socket.
pub unsafe fn sendto_nocancel(
    sockfd: i32,
    buf: &[u8],
    flags: i32,
    dest_addr: caddr_t,
    addrlen: socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let len = buf.len();
    let flags = flags as usize;
    let dest_addr_ptr = core::ptr::from_ref(dest_addr) as usize;
    let addrlen = addrlen as usize;
    unsafe {
        syscall6(
            SYS_SENDTO_NOCANCEL,
            sockfd,
            buf_ptr,
            len,
            flags,
            dest_addr_ptr,
            addrlen,
        )
        .map(|ret| ret as ssize_t)
    }
}

/// Set audit session state
pub unsafe fn setaudit_addr(info: &mut auditinfo_addr_t, length: u32) -> Result<(), Errno> {
    let info_ptr = core::ptr::from_mut(info) as usize;
    let length = length as usize;
    unsafe { syscall2(SYS_SETAUDIT_ADDR, info_ptr, length).map(drop) }
}

/// Set audit session ID
pub unsafe fn setauid(auid: &mut au_id_t) -> Result<(), Errno> {
    let auid_ptr = core::ptr::from_mut(auid) as usize;
    unsafe { syscall1(SYS_SETAUID, auid_ptr).map(drop) }
}

/// Set the effective group ID of the calling process to `gid`.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setegid(0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setegid(gid: gid_t) -> Result<(), Errno> {
    let gid = gid as usize;
    unsafe { syscall1(SYS_SETEGID, gid).map(drop) }
}

/// Set the effective user ID of the calling process to `uid`.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::seteuid(0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn seteuid(uid: uid_t) -> Result<(), Errno> {
    let uid = uid as usize;
    unsafe { syscall1(SYS_SETEUID, uid).map(drop) }
}

/// Set the group ID of the calling process to `gid`.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setgid(0) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setgid(gid: gid_t) -> Result<(), Errno> {
    let gid = gid as usize;
    unsafe { syscall1(SYS_SETGID, gid).map(drop) }
}

/// Set list of supplementary group Ids.
///
/// # Examples
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
    unsafe { syscall2(SYS_SETGROUPS, group_len, group_ptr).map(drop) }
}

/// Set value of an interval timer.
///
/// # Examples
///
/// ```
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
///     let msg = b"Hello alarm\n";
///     let stderr = 2;
///     let _ = unsafe { nc::write(stderr, msg) };
/// }
///
/// let sa = nc::new_sigaction(handle_alarm);
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
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
/// let ret = unsafe { nc::setitimer(nc::ITIMER_REAL, &itv, None) };
/// assert!(ret.is_ok());
///
/// let mut prev_itv = nc::itimerval_t::default();
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);
///
/// let mask = nc::sigset_t::default();
/// let _ret = unsafe { nc::rt_sigsuspend(&mask) };
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert_eq!(prev_itv.it_value.tv_sec, 0);
/// assert_eq!(prev_itv.it_value.tv_usec, 0);
/// ```
pub unsafe fn setitimer(
    which: i32,
    new_val: &itimerval_t,
    old_val: Option<&mut itimerval_t>,
) -> Result<(), Errno> {
    let which = which as usize;
    let new_val_ptr = core::ptr::from_ref(new_val) as usize;
    let old_val_ptr = old_val.map_or(core::ptr::null_mut::<itimerval_t>() as usize, |old_val| {
        core::ptr::from_mut(old_val) as usize
    });
    unsafe { syscall3(SYS_SETITIMER, which, new_val_ptr, old_val_ptr).map(drop) }
}

/// Set login name.
pub unsafe fn setlogin(name: &str) -> Result<(), Errno> {
    let name = CString::new(name);
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall1(SYS_SETLOGIN, name_ptr).map(drop) }
}

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setpgid(nc::getpid(), 1) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let pgid = pgid as usize;
    unsafe { syscall2(SYS_SETPGID, pid, pgid).map(drop) }
}

/// Set program scheduling priority.
///
/// # Examples
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
    unsafe { syscall3(SYS_SETPRIORITY, which, who, prio).map(drop) }
}

/// Set real and effective group IDs of the calling process.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setregid(0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setregid(rgid: gid_t, egid: gid_t) -> Result<(), Errno> {
    let rgid = rgid as usize;
    let egid = egid as usize;
    unsafe { syscall2(SYS_SETREGID, rgid, egid).map(drop) }
}

/// Set real and effective user IDs of the calling process.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setreuid(0, 0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), Errno> {
    let ruid = ruid as usize;
    let euid = euid as usize;
    unsafe { syscall2(SYS_SETREUID, ruid, euid).map(drop) }
}

/// Set resource limit.
///
/// # Examples
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
    let rlimit_ptr = core::ptr::from_ref(rlimit) as usize;
    unsafe { syscall2(SYS_SETRLIMIT, resource, rlimit_ptr).map(drop) }
}

/// Create a new session if the calling process is not a process group leader.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setsid() };
/// assert!(ret.is_ok());
/// let pid = unsafe { nc::getpid() };
/// assert_eq!(ret, Ok(pid));
/// ```
pub unsafe fn setsid() -> Result<pid_t, Errno> {
    unsafe { syscall0(SYS_SETSID).map(|ret| ret as pid_t) }
}

/// Set options on sockets.
///
/// # Examples
///
/// ```
/// let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
/// assert!(socket_fd.is_ok());
/// let socket_fd = socket_fd.unwrap();
///
/// // Enable tcp fast open.
/// let queue_len: i32 = 5;
/// let ret = unsafe {
///     nc::setsockopt(
///         socket_fd,
///         nc::IPPROTO_TCP,
///         nc::TCP_FASTOPEN,
///         &queue_len as *const i32 as *const _,
///         std::mem::size_of_val(&queue_len) as nc::socklen_t,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::close(socket_fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setsockopt(
    sockfd: i32,
    level: i32,
    opt_name: i32,
    opt_val: *const core::ffi::c_void,
    opt_len: socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let opt_name = opt_name as usize;
    let opt_val = opt_val as usize;
    let opt_len = opt_len as usize;
    unsafe { syscall5(SYS_SETSOCKOPT, sockfd, level, opt_name, opt_val, opt_len).map(drop) }
}

/// Set the per-thread override identity.
pub unsafe fn settid(uid: uid_t, gid: gid_t) -> Result<(), Errno> {
    let uid = uid as usize;
    let gid = gid as usize;
    unsafe { syscall2(SYS_SETTID, uid, gid).map(drop) }
}

/// Set the per-thread override identity.
pub unsafe fn settid_with_pid(pid: pid_t, assume: i32) -> Result<(), Errno> {
    let pid = pid as usize;
    let assume = assume as usize;
    unsafe { syscall2(SYS_SETTID_WITH_PID, pid, assume).map(drop) }
}

/// Set system time and timezone.
///
/// ```
/// let tv = nc::timeval_t {
///     tv_sec: 1,
///     tv_usec: 0,
/// };
/// let ret = unsafe { nc::settimeofday(&tv, None) };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn settimeofday(timeval: &timeval_t, tz: Option<&timezone_t>) -> Result<(), Errno> {
    let timeval_ptr = core::ptr::from_ref(timeval) as usize;
    let tz_ptr = tz.map_or(core::ptr::null::<timezone_t>() as usize, |tz| {
        core::ptr::from_ref(tz) as usize
    });
    unsafe { syscall2(SYS_SETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop) }
}

/// Set user ID of the calling process to `uid`.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::setuid(0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setuid(uid: uid_t) -> Result<(), Errno> {
    let uid = uid as usize;
    unsafe { syscall1(SYS_SETUID, uid).map(drop) }
}

/// Set extended attribute value.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-setxattr";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let attr_name = "user.creator";
/// let attr_value = "nc-0.0.1";
/// //let flags = 0;
/// let flags = nc::XATTR_CREATE;
/// let ret = unsafe {
///     nc::setxattr(
///         path,
///         &attr_name,
///         attr_value.as_bytes(),
///         flags,
///     )
/// };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setxattr<P: AsRef<Path>>(
    filename: P,
    name: P,
    value: &[u8],
    flags: i32,
) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let value_ptr = value.as_ptr() as usize;
    let size = value.len();
    let flags = flags as usize;
    unsafe { syscall5(SYS_SETXATTR, filename_ptr, name_ptr, value_ptr, size, flags).map(drop) }
}

/// Attach the System V shared memory segment.
///
/// # Examples
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let shmid = ret.unwrap();
///
/// let ret = unsafe { nc::shmat(shmid, None, 0) };
/// assert!(ret.is_ok());
/// let addr: *const std::ffi::c_void = ret.unwrap();
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
pub unsafe fn shmat(
    shmid: i32,
    shm_addr: Option<*const core::ffi::c_void>,
    shm_flag: i32,
) -> Result<*const core::ffi::c_void, Errno> {
    let shmid = shmid as usize;
    let shm_addr = shm_addr.map_or(core::ptr::null::<u8>() as usize, |shm_addr| {
        shm_addr as usize
    });
    let shm_flag = shm_flag as usize;
    unsafe {
        syscall3(SYS_SHMAT, shmid, shm_addr, shm_flag).map(|ret| ret as *const core::ffi::c_void)
    }
}

/// System V shared memory control.
///
/// # Examples
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
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall3(SYS_SHMCTL, shmid, cmd, buf_ptr).map(|ret| ret as i32) }
}

/// Detach the System V shared memory segment.
///
/// # Examples
///
/// ```
/// let size = 4 * nc::PAGE_SIZE;
/// let flags = nc::IPC_CREAT | nc::IPC_EXCL | 0o600;
/// let ret = unsafe { nc::shmget(nc::IPC_PRIVATE, size, flags) };
/// assert!(ret.is_ok());
/// let shmid = ret.unwrap();
///
/// let ret = unsafe { nc::shmat(shmid, None, 0) };
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
pub unsafe fn shmdt(shm_addr: *const core::ffi::c_void) -> Result<(), Errno> {
    let shm_addr = shm_addr as usize;
    unsafe { syscall1(SYS_SHMDT, shm_addr).map(drop) }
}

/// Allocates a System V shared memory segment.
///
/// # Examples
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
pub unsafe fn shmget(key: key_t, size: size_t, shm_flag: i32) -> Result<i32, Errno> {
    let key = key as usize;
    let shm_flag = shm_flag as usize;
    unsafe { syscall3(SYS_SHMGET, key, size, shm_flag).map(|ret| ret as i32) }
}

pub unsafe fn shmsys(which: i32, a2: i32, a3: i32, a4: i32) -> Result<(), Errno> {
    let which = which as usize;
    let a2 = a2 as usize;
    let a3 = a3 as usize;
    let a4 = a4 as usize;
    unsafe { syscall4(SYS_SHMSYS, which, a2, a3, a4).map(drop) }
}

/// Opens (or optionally creates) a POSIX shared memory object named `path`.
pub unsafe fn shm_open<P: AsRef<Path>>(name: P, flags: i32, mode: i32) -> Result<i32, Errno> {
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    unsafe { syscall3(SYS_SHM_OPEN, name_ptr, flags, mode).map(|val| val as i32) }
}

/// Removes a shared memory object named `path`.
pub unsafe fn shm_unlink<P: AsRef<Path>>(path: P) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    unsafe { syscall1(SYS_SHM_UNLINK, path_ptr).map(drop) }
}

/// Shutdown part of a full-duplex connection.
///
/// # Examples
///
/// ```
/// use nc::Errno;
/// use std::mem::{size_of, transmute};
/// use std::thread;
///
/// const SERVER_PORT: u16 = 18087;
///
/// #[must_use]
/// #[inline]
/// const fn htons(host: u16) -> u16 {
///     host.to_be()
/// }
///
/// fn main() -> Result<(), Errno> {
///     let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };
///     println!("listen fd: {listen_fd}");
///
///     let addr = nc::sockaddr_in_t {
///         sin_family: nc::AF_INET as nc::sa_family_t,
///         sin_port: htons(SERVER_PORT),
///         sin_addr: nc::in_addr_t {
///             s_addr: nc::INADDR_ANY as u32,
///         },
///         ..Default::default()
///     };
///     println!("addr: {addr:?}");
///
///     let ret = unsafe {
///         let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///         nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32)
///     };
///     assert!(ret.is_ok());
///
///     // Start worker thread
///     thread::spawn(|| {
///         println!("worker thread started");
///         let socket_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0) };
///         assert!(socket_fd.is_ok());
///         if let Ok(socket_fd) = socket_fd {
///             let addr = nc::sockaddr_in_t {
///                 sin_family: nc::AF_INET as nc::sa_family_t,
///                 sin_port: htons(SERVER_PORT),
///                 sin_addr: nc::in_addr_t {
///                     s_addr: nc::INADDR_ANY as u32,
///                 },
///                 ..Default::default()
///             };
///             unsafe {
///                 let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
///                 let ret = nc::connect(socket_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
///                 assert_eq!(ret, Ok(()));
///
///                 let _ = nc::shutdown(socket_fd, nc::SHUT_RDWR);
///             }
///         } else {
///             eprintln!("Failed to create socket");
///         }
///     });
///
///     unsafe {
///         nc::listen(listen_fd, nc::SOCK_STREAM)?;
///     }
///
///     let conn_fd = unsafe {
///         nc::accept4(listen_fd, None, None, nc::SOCK_CLOEXEC)?
///     };
///     println!("conn_fd: {conn_fd}");
///
///     unsafe {
///         nc::close(listen_fd)?;
///     }
///
///     Ok(())
/// }
/// ```
pub unsafe fn shutdown(sockfd: i32, how: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let how = how as usize;
    unsafe { syscall2(SYS_SHUTDOWN, sockfd, how).map(drop) }
}

/// Examine and change a signal action.
///
/// # Examples
///
/// ```
/// fn handle_sigterm(sig: i32) {
///     assert_eq!(sig, nc::SIGTERM);
/// }
///
/// let sa = nc::new_sigaction(handle_sigterm);
/// let ret = unsafe { nc::sigaction(nc::SIGTERM, Some(&sa), None) };
/// let ret = unsafe { nc::kill(nc::getpid(), nc::SIGTERM) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sigaction(
    sig: i32,
    act: Option<&sigaction_t>,
    old_act: Option<&mut sigaction_t>,
) -> Result<(), Errno> {
    let sig = sig as usize;
    let act_ptr = act.map_or(core::ptr::null::<sigaction_t>() as usize, |act| {
        core::ptr::from_ref(act) as usize
    });
    let old_act_ptr = old_act.map_or(core::ptr::null_mut::<sigaction_t>() as usize, |old_act| {
        core::ptr::from_mut(old_act) as usize
    });
    unsafe { syscall3(SYS_SIGACTION, sig, act_ptr, old_act_ptr).map(drop) }
}

/// Get/set signal stack context.
pub unsafe fn sigaltstack(
    ss: Option<&sigaltstack_t>,
    old_ss: Option<&mut sigaltstack_t>,
) -> Result<(), Errno> {
    let ss_ptr = ss.map_or(core::ptr::null::<sigaltstack_t>() as usize, |ss| {
        core::ptr::from_ref(ss) as usize
    });
    let old_ss_ptr = old_ss.map_or(core::ptr::null_mut::<sigaltstack_t>() as usize, |old_ss| {
        core::ptr::from_mut(old_ss) as usize
    });
    unsafe { syscall2(SYS_SIGALTSTACK, ss_ptr, old_ss_ptr).map(drop) }
}

/// Examine pending signals.
pub unsafe fn sigpending(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = core::ptr::from_mut(set) as usize;
    unsafe { syscall1(SYS_SIGPENDING, set_ptr).map(drop) }
}

/// Examine and change blocked signals.
pub unsafe fn sigprocmask(
    how: i32,
    newset: &mut sigset_t,
    oldset: &mut sigset_t,
) -> Result<(), Errno> {
    let how = how as usize;
    let newset_ptr = core::ptr::from_mut(newset) as usize;
    let oldset_ptr = core::ptr::from_mut(oldset) as usize;
    unsafe { syscall3(SYS_SIGPROCMASK, how, newset_ptr, oldset_ptr).map(drop) }
}

/// Return from signal handler and cleanup stack frame.
/// Never returns.
pub unsafe fn sigreturn() {
    let _ = unsafe { syscall0(SYS_SIGRETURN) };
}

/// Wait for a signal.
pub unsafe fn sigsuspend(mask: &sigset_t) -> Result<(), Errno> {
    let mask_ptr = core::ptr::from_ref(mask) as usize;
    unsafe { syscall1(SYS_SIGSUSPEND, mask_ptr).map(drop) }
}

/// Create an endpoint for communication.
///
/// # Examples
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
    unsafe { syscall3(SYS_SOCKET, domain, sock_type, protocol).map(|ret| ret as i32) }
}

/// Create a pair of connected socket.
///
/// # Examples
///
/// ```
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// let mut fds = [-1_i32; 2];
///
/// let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
/// assert!(ret.is_ok());
/// println!("socket pairs: {}, {}", fds[0], fds[1]);
///
/// // Start worker thread
/// thread::spawn(move || {
///     println!("worker thread started");
///     let msg = "Hello, Rust";
///     println!("[worker] Will send msg: {msg}");
///     let ret = unsafe { nc::write(fds[WRITE_SIDE], msg.as_bytes()) };
///     assert!(ret.is_ok());
///     assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// });
///
/// let mut buf = [0_u8; 1024];
/// let ret = unsafe { nc::read(fds[READ_SIDE], &mut buf) };
/// assert!(ret.is_ok());
/// let nread = ret.unwrap();
/// let msg = std::str::from_utf8(&buf[..nread as usize]).unwrap();
/// println!("[main] recv msg: {msg}");
///
/// unsafe {
///     let _ = nc::close(fds[0]);
///     let _ = nc::close(fds[1]);
/// }
/// ```
pub unsafe fn socketpair(
    domain: i32,
    type_: i32,
    protocol: i32,
    pair: &mut [i32; 2],
) -> Result<(), Errno> {
    let domain = domain as usize;
    let type_ = type_ as usize;
    let protocol = protocol as usize;
    let pair_ptr = pair.as_mut_ptr() as usize;
    unsafe { syscall4(SYS_SOCKETPAIR, domain, type_, protocol, pair_ptr).map(drop) }
}

/// Get file status about a file.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat_t::default();
/// let ret = unsafe { nc::stat(path, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a regular file.
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// ```
pub unsafe fn stat<P: AsRef<Path>>(filename: P, statbuf: &mut stat_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_STAT, filename_ptr, statbuf_ptr).map(drop) }
}

/// Get file status about a file.
///
/// # Examples
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat64_t::default();
/// let ret = unsafe { nc::stat64(path, &mut stat) };
/// assert!(ret.is_ok());
/// // Check fd is a regular file.
/// assert!(nc::S_ISREG(stat.st_mode as nc::mode_t));
/// ```
pub unsafe fn stat64<P: AsRef<Path>>(filename: P, statbuf: &mut stat64_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS_STAT64, filename_ptr, statbuf_ptr).map(drop) }
}

/// Get filesystem statistics.
///
/// # Examples
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
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall2(SYS_STATFS, filename_ptr, buf_ptr).map(drop) }
}

/// Get filesystem statistics.
///
/// # Examples
///
/// ```
/// let path = "/usr";
/// let mut statfs = nc::statfs64_t::default();
/// let ret = unsafe { nc::statfs64(path, &mut statfs) };
/// assert!(ret.is_ok());
/// assert!(statfs.f_bfree > 0);
/// assert!(statfs.f_bavail > 0);
/// ```
pub unsafe fn statfs64<P: AsRef<Path>>(filename: P, buf: &mut statfs64_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall2(SYS_STATFS64, filename_ptr, buf_ptr).map(drop) }
}

/// Start swapping to file/device.
///
/// # Examples
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
    unsafe { syscall2(SYS_SWAPON, filename_ptr, flags).map(drop) }
}

/// Make a new name for a file.
///
/// # Examples
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-symlink";
/// let ret = unsafe { nc::symlink(oldname, newname) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, newname,0 ) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn symlink<P: AsRef<Path>>(old_name: P, new_name: P) -> Result<(), Errno> {
    let old_name = CString::new(old_name.as_ref());
    let old_name_ptr = old_name.as_ptr() as usize;
    let new_name = CString::new(new_name.as_ref());
    let new_name_ptr = new_name.as_ptr() as usize;
    unsafe { syscall2(SYS_SYMLINK, old_name_ptr, new_name_ptr).map(drop) }
}

/// Make a new name for a file.
///
/// # Examples
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
    old_name: P,
    new_dirfd: i32,
    new_name: P,
) -> Result<(), Errno> {
    let old_name = CString::new(old_name.as_ref());
    let old_name_ptr = old_name.as_ptr() as usize;
    let new_dirfd = new_dirfd as usize;
    let new_name = CString::new(new_name.as_ref());
    let new_name_ptr = new_name.as_ptr() as usize;
    unsafe { syscall3(SYS_SYMLINKAT, old_name_ptr, new_dirfd, new_name_ptr).map(drop) }
}

/// Commit filesystem caches to disk.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::sync() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sync() -> Result<(), Errno> {
    unsafe { syscall0(SYS_SYNC).map(drop) }
}

/// Truncate a file to a specified length.
///
/// # Examples
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
    unsafe { syscall2(SYS_TRUNCATE, filename_ptr, length).map(drop) }
}

/// Set file mode creation mask.
///
/// # Examples
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
    unsafe { syscall1(SYS_UMASK, mode).map(|ret| ret as mode_t) }
}

/// Attempt to recover a deleted file
pub unsafe fn undelete<P: AsRef<Path>>(path: P) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    unsafe { syscall1(SYS_UNDELETE, path_ptr).map(drop) }
}

/// Delete a name and possibly the file it refers to.
///
/// # Examples
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
    unsafe { syscall1(SYS_UNLINK, filename_ptr).map(drop) }
}

/// Delete a name and possibly the file it refers to.
///
/// # Examples
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
    unsafe { syscall3(SYS_UNLINKAT, dfd, filename_ptr, flag).map(drop) }
}

/// Unmount filesystem.
pub unsafe fn unmount<P: AsRef<Path>>(path: P, flags: i32) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_UNMOUNT, path_ptr, flags).map(drop) }
}

/// Change file last access and modification time.
///
/// # Examples
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
    unsafe { syscall2(SYS_UTIMES, filename_ptr, times_ptr).map(drop) }
}

/// Create a child process and wait until it is terminated.
pub unsafe fn vfork() -> Result<pid_t, Errno> {
    unsafe { syscall0(SYS_VFORK).map(|ret| ret as pid_t) }
}

/// Wait for process to change state.
///
/// # Examples
///
/// ```
/// let pid = unsafe { nc::fork() };
///
/// match pid {
///     Err(errno) => {
///         eprintln!("fork() error: {}", nc::strerror(errno));
///         unsafe { nc::exit(1) };
///     }
///     Ok(0) => println!("[child] pid is: {}", unsafe { nc::getpid() }),
///     Ok(pid) => {
///         let mut status = 0;
///         let ret = unsafe { nc::wait4(-1, Some(&mut status), 0, None) };
///         assert!(ret.is_ok());
///         println!("status: {}", status);
///         let exited_pid = ret.unwrap();
///         assert_eq!(exited_pid, pid);
///     }
/// }
/// ```
pub unsafe fn wait4(
    pid: pid_t,
    wstatus: Option<&mut i32>,
    options: i32,
    rusage: Option<&mut rusage_t>,
) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    let wstatus_ptr = wstatus.map_or(core::ptr::null_mut::<i32>() as usize, |wstatus| {
        core::ptr::from_mut(wstatus) as usize
    });
    let options = options as usize;
    let rusage_ptr = rusage.map_or(core::ptr::null_mut::<rusage_t>() as usize, |rusage| {
        core::ptr::from_mut(rusage) as usize
    });
    unsafe { syscall4(SYS_WAIT4, pid, wstatus_ptr, options, rusage_ptr).map(|ret| ret as pid_t) }
}

/// Wait for process to change state.
///
/// # Examples
///
/// ```
/// let pid = unsafe { nc::fork() };
///
/// match pid {
///     Err(errno) => {
///         eprintln!("fork() error: {}", nc::strerror(errno));
///         unsafe { nc::exit(1) };
///     }
///     Ok(0) => println!("[child] pid is: {}", unsafe { nc::getpid() }),
///     Ok(pid) => {
///         let mut info = nc::siginfo_t::default();
///         let options = nc::WEXITED;
///         let ret = unsafe { nc::waitid(nc::P_ALL, -1, &mut info, options, None) };
///         match ret {
///             Err(errno) => eprintln!("waitid() error: {}", nc::strerror(errno)),
///             Ok(()) => {
///                 let exited_pid = unsafe { info.siginfo.sifields.sigchld.pid };
///                 assert_eq!(pid, exited_pid);
///             }
///         }
///     }
/// }
/// ```
pub unsafe fn waitid(
    which: i32,
    pid: pid_t,
    info: &mut siginfo_t,
    options: i32,
    ru: Option<&mut rusage_t>,
) -> Result<(), Errno> {
    let which = which as usize;
    let pid = pid as usize;
    let info_ptr = core::ptr::from_mut(info) as usize;
    let options = options as usize;
    let ru_ptr = ru.map_or(core::ptr::null_mut::<rusage_t>() as usize, |ru| {
        core::ptr::from_mut(ru) as usize
    });
    unsafe { syscall5(SYS_WAITID, which, pid, info_ptr, options, ru_ptr).map(drop) }
}

/// Write to a file descriptor.
///
/// # Examples
///
/// ```
/// let path = "/tmp/nc-write";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_CREAT | nc::O_WRONLY, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let msg = b"Hello, Rust!";
/// let ret = unsafe { nc::write(fd, msg) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn write(fd: i32, buf: &[u8]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let count = buf.len();
    let buf_ptr = buf.as_ptr() as usize;
    unsafe { syscall3(SYS_WRITE, fd, buf_ptr, count).map(|ret| ret as ssize_t) }
}

/// Write to a file descriptor from multiple buffers.
///
/// # Examples
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
/// let ret = unsafe { nc::readv(fd as usize, &mut iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
///
/// let path_out = "/tmp/nc-writev";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path_out, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = unsafe { nc::writev(fd as usize, &iov) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path_out, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn writev(fd: usize, iov: &[iovec_t]) -> Result<ssize_t, Errno> {
    let iov_ptr = iov.as_ptr() as usize;
    let len = iov.len();
    unsafe { syscall3(SYS_WRITEV, fd, iov_ptr, len).map(|ret| ret as ssize_t) }
}

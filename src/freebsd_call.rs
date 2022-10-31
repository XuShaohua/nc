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

use crate::c_str::{strlen, CString};
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

/// Terminate current process.
///
/// ```
/// nc::exit(0);
/// ```
pub unsafe fn exit(status: i32) {
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
pub unsafe fn read(fd: i32, buf: usize, count: size_t) -> Result<ssize_t, Errno> {
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
pub unsafe fn write(fd: i32, buf_ptr: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_WRITE, fd, buf_ptr, count).map(|ret| ret as ssize_t)
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
pub unsafe fn open<P: AsRef<Path>>(path: P, flags: i32, mode: mode_t) -> Result<i32, Errno> {
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
pub unsafe fn close(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_CLOSE, fd).map(drop)
}

/// Wait for process to change state.
///
/// ```
/// let ret = nc::fork();
/// match ret {
///     Err(errno) => {
///         eprintln!("fork() error: {}", nc::strerror(errno));
///         nc::exit(1);
///     }
///     Ok(0) => println!("[child] pid is: {}", nc::getpid()),
///     Ok(pid) => {
///         let mut status = 0;
///         let mut usage = nc::rusage_t::default();
///         let ret = nc::wait4(-1, &mut status, 0, &mut usage);
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
pub unsafe fn link<P: AsRef<Path>>(old_filename: P, new_filename: P) -> Result<(), Errno> {
    let old_filename = CString::new(old_filename.as_ref());
    let old_filename_ptr = old_filename.as_ptr() as usize;
    let new_filename = CString::new(new_filename.as_ref());
    let new_filename_ptr = new_filename.as_ptr() as usize;
    syscall2(SYS_LINK, old_filename_ptr, new_filename_ptr).map(drop)
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
pub unsafe fn unlink<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_UNLINK, filename_ptr).map(drop)
}

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
pub unsafe fn chdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_CHDIR, filename_ptr).map(drop)
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
pub unsafe fn fchdir(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FCHDIR, fd).map(drop)
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
pub unsafe fn chmod<P: AsRef<Path>>(filename: P, mode: mode_t) -> Result<(), Errno> {
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
pub unsafe fn chown<P: AsRef<Path>>(filename: P, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_CHOWN, filename_ptr, user, group).map(drop)
}

/// Get the process ID (PID) of the calling process.
///
/// ```
/// let pid = nc::getpid();
/// assert!(pid > 0);
/// ```
#[must_use]
pub unsafe fn getpid() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPID).expect("getpid() failed") as pid_t
}

/// Mount filesystem.
///
/// ```
/// let target_dir = "/tmp/nc-mount";
/// let ret = nc::mkdir(target_dir, 0o755);
/// assert!(ret.is_ok());
///
/// let src_dir = "/etc";
/// let fs_type = "";
/// let mount_flags = nc::MNT_RDONLY;
/// let data = 0;
/// let ret = nc::mount(fs_type, target_dir, mount_flags, data);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
///
/// assert!(nc::rmdir(target_dir).is_ok());
/// ```
pub unsafe fn mount<P: AsRef<Path>>(
    fs_type: &str,
    path: P,
    flags: i32,
    data: usize,
) -> Result<(), Errno> {
    let fs_type = CString::new(fs_type);
    let fs_type_ptr = fs_type.as_ptr() as usize;
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    syscall4(SYS_MOUNT, fs_type_ptr, path_ptr, flags, data).map(drop)
}

/// Dismount a file system.
pub unsafe fn unmount<P: AsRef<Path>>(path: P, flags: i32) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    syscall2(SYS_UNMOUNT, path_ptr, flags).map(drop)
}

/// Create a child process.
///
/// ```
/// let pid = nc::fork();
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// ```
pub unsafe fn fork() -> Result<pid_t, Errno> {
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
pub unsafe fn getcwd(buf: usize, size: size_t) -> Result<ssize_t, Errno> {
    __getcwd(buf, size)?;
    Ok(strlen(buf, size) as ssize_t + 1)
}

/// Get current working directory.
pub unsafe fn __getcwd(buf: usize, size: size_t) -> Result<(), Errno> {
    syscall2(SYS___GETCWD, buf, size).map(drop)
}

/// Get the real user ID of the calling process.
///
/// ```
/// let uid = nc::getuid();
/// assert!(uid > 0);
/// ```
#[must_use]
pub unsafe fn getuid() -> uid_t {
    // This function is always successful.
    syscall0(SYS_GETUID).expect("getuid() failed") as uid_t
}

/// Get the effective user ID of the calling process.
///
/// ```
/// let euid = nc::geteuid();
/// assert!(euid > 0);
/// ```
#[must_use]
pub unsafe fn geteuid() -> uid_t {
    // This function is always successful.
    syscall0(SYS_GETEUID).expect("geteuid() failed") as uid_t
}

/// Receives multile messages on a socket
pub unsafe fn recvmsg(sockfd: i32, msg: &mut msghdr_t, flags: i32) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = msg as *mut msghdr_t as usize;
    let flags = flags as usize;
    syscall3(SYS_RECVMSG, sockfd, msg_ptr, flags).map(|ret| ret as i32)
}

/// Send a message on a socket. Allow sending ancillary data.
pub unsafe fn sendmsg(sockfd: i32, msg: &msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let msg_ptr = msg as *const msghdr_t as usize;
    let flags = flags as usize;
    syscall3(SYS_SENDMSG, sockfd, msg_ptr, flags).map(|ret| ret as ssize_t)
}

/// Receive a message from a socket.
pub unsafe fn recvfrom(
    sockfd: i32,
    buf_ptr: usize,
    buf_len: size_t,
    flags: i32,
    src_addr: &mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let flags = flags as usize;
    let src_addr_ptr = src_addr as *mut sockaddr_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall6(
        SYS_RECVFROM,
        sockfd,
        buf_ptr,
        buf_len,
        flags,
        src_addr_ptr,
        addrlen_ptr,
    )
    .map(|ret| ret as ssize_t)
}

/// Accept a connection on a socket.
pub unsafe fn accept(
    sockfd: i32,
    addr: &mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Get name of connected peer socket.
pub unsafe fn getpeername(
    sockfd: i32,
    addr: &mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_GETPEERNAME, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Get current address to which the socket `sockfd` is bound.
pub unsafe fn getsockname(
    sockfd: i32,
    addr: &mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_GETSOCKNAME, sockfd, addr_ptr, addrlen_ptr).map(drop)
}

/// Check user's permission for a file.
///
/// ```
/// assert!(nc::access("/etc/passwd", nc::F_OK).is_ok());
/// assert!(nc::access("/etc/passwd", nc::X_OK).is_err());
/// ```
pub unsafe fn access<P: AsRef<Path>>(filename: P, mode: i32) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_ACCESS, filename_ptr, mode).map(drop)
}

/// Commit filesystem caches to disk.
///
/// ```
/// assert!(nc::sync().is_ok());
/// ```
pub unsafe fn sync() -> Result<(), Errno> {
    syscall0(SYS_SYNC).map(drop)
}

/// Send signal to a process.
///
/// ```
/// let pid = nc::fork();
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// if pid == 0 {
///     // child process.
///     let args = [""];
///     let env = [""];
///     let ret = nc::execve("/usr/bin/yes", &args, &env);
///     assert!(ret.is_ok());
/// } else {
///     // parent process.
///     let ret = nc::kill(pid, nc::SIGTERM);
///     assert!(ret.is_ok());
/// }
/// ```
pub unsafe fn kill(pid: pid_t, signal: i32) -> Result<(), Errno> {
    let pid = pid as usize;
    let signal = signal as usize;
    syscall2(SYS_KILL, pid, signal).map(drop)
}

/// Get the process ID of the parent of the calling process.
///
/// ```
/// let ppid = nc::getppid();
/// assert!(ppid > 0);
/// ```
#[must_use]
pub unsafe fn getppid() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPPID).expect("getppid() failed") as pid_t
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
///
/// ```
/// let path = "/tmp/nc-dup-file";
/// let fd = nc::creat(path, 0o644);
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let fd_dup = nc::dup(fd);
/// assert!(fd_dup.is_ok());
/// let fd_dup = fd_dup.unwrap();
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::close(fd_dup).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn dup(oldfd: i32) -> Result<i32, Errno> {
    let oldfd = oldfd as usize;
    syscall1(SYS_DUP, oldfd).map(|ret| ret as i32)
}

/// Get the effective group ID of the calling process.
///
/// ```
/// let egid = nc::getegid();
/// assert!(egid > 0);
/// ```
#[must_use]
pub unsafe fn getegid() -> gid_t {
    // This function is always successful.
    syscall0(SYS_GETEGID).expect("getegid() failed") as gid_t
}

/// Get the real group ID of the calling process.
///
/// ```
/// let gid = nc::getgid();
/// assert!(gid > 0);
/// ```
#[must_use]
pub unsafe fn getgid() -> gid_t {
    // This function is always successful.
    syscall0(SYS_GETGID).expect("getgid() failed") as gid_t
}

/// Switch process accounting.
///
/// ```
/// let path = "/tmp/nc-acct";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let ret = nc::acct(path);
/// assert_eq!(ret, Err(nc::EPERM));
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn acct<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_ACCT, filename_ptr).map(drop)
}

/// Get/set signal stack context.
pub unsafe fn sigaltstack(uss: &sigaltstack_t, uoss: &mut sigaltstack_t) -> Result<(), Errno> {
    let uss_ptr = uss as *const sigaltstack_t as usize;
    let uoss_ptr = uoss as *mut sigaltstack_t as usize;
    syscall2(SYS_SIGALTSTACK, uss_ptr, uoss_ptr).map(drop)
}

/// Control device.
///
/// ```
/// let path = "/tmp/nc-ioctl";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut attr: i32 = 0;
/// let cmd = -2146933247; // nc::FS_IOC_GETFLAGS
/// let ret = nc::ioctl(fd, cmd, &mut attr as *mut i32 as usize);
/// assert!(ret.is_ok());
/// println!("attr: {}", attr);
///
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn ioctl(fd: i32, cmd: i32, arg: usize) -> Result<(), Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    syscall3(SYS_IOCTL, fd, cmd, arg).map(drop)
}

/// Reboot system or halt processor.
///
/// ```
/// let ret = nc::reboot(nc::RB_AUTOBOOT);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn reboot(opt: i32) -> Result<(), Errno> {
    let opt = opt as usize;
    syscall1(SYS_REBOOT, opt).map(drop)
}

/// Make a new name for a file.
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-symlink";
/// let ret = nc::symlink(oldname, newname);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(newname).is_ok());
/// ```
pub unsafe fn symlink<P: AsRef<Path>>(oldname: P, newname: P) -> Result<(), Errno> {
    let oldname = CString::new(oldname.as_ref());
    let oldname_ptr = oldname.as_ptr() as usize;
    let newname = CString::new(newname.as_ref());
    let newname_ptr = newname.as_ptr() as usize;
    syscall2(SYS_SYMLINK, oldname_ptr, newname_ptr).map(drop)
}

/// Read value of a symbolic link.
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlink";
/// let ret = nc::symlink(oldname, newname);
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize];
/// let buf_len = buf.len();
/// let ret = nc::readlink(newname, &mut buf, buf_len);
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap() as usize;
/// assert_eq!(n_read, oldname.len());
/// assert_eq!(oldname.as_bytes(), &buf[0..n_read]);
/// assert!(nc::unlink(newname).is_ok());
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

/// Execute a new program.
///
/// TODO(Shaohua): type of argv and env will be changed.
/// And return value might be changed too.
/// ```
/// let pid = nc::fork();
/// assert!(pid.is_ok());
/// let pid = pid.unwrap();
/// assert!(pid >= 0);
/// if pid == 0 {
///     // child process
///     let args = [""];
///     let env = [""];
///     let ret = nc::execve("/bin/ls", &args, &env);
///     assert!(ret.is_ok());
/// }
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

/// Set file mode creation mask.
///
/// ```
/// let new_mask = 0o077;
/// let ret = nc::umask(new_mask);
/// assert!(ret.is_ok());
/// let old_mask = ret.unwrap();
/// let ret = nc::umask(old_mask);
/// assert_eq!(ret, Ok(new_mask));
/// ```
pub unsafe fn umask(new_mask: mode_t) -> Result<mode_t, Errno> {
    let new_mask = new_mask as usize;
    syscall1(SYS_UMASK, new_mask).map(|ret| ret as mode_t)
}

/// Change the root directory.
///
/// ```
/// let ret = nc::chroot("/");
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn chroot<P: AsRef<Path>>(path: P) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    syscall1(SYS_CHROOT, path_ptr).map(drop)
}

/// Synchronize a file with memory map.
pub unsafe fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    let len = len as usize;
    let flags = flags as usize;
    syscall3(SYS_MSYNC, addr, len, flags).map(drop)
}

/// Create a child process and wait until it is terminated.
pub unsafe fn vfork() -> Result<pid_t, Errno> {
    syscall0(SYS_VFORK).map(|ret| ret as pid_t)
}

/// Unmap files or devices from memory.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let mut sb = nc::stat_t::default();
/// let ret = nc::fstat(fd, &mut sb);
/// assert!(ret.is_ok());
///
/// let offset: usize = 0;
/// let length: usize = sb.st_size as usize - offset;
/// // Offset for mmap must be page aligned.
/// let pa_offset: usize = offset & !(nc::PAGE_SIZE - 1);
/// let map_length = length + offset - pa_offset;
///
/// let addr = nc::mmap(
///     0, // 0 as NULL
///     map_length,
///     nc::PROT_READ,
///     nc::MAP_PRIVATE,
///     fd,
///     pa_offset as nc::off_t,
/// );
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// let n_write = nc::write(1, addr + offset - pa_offset, length);
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// assert!(nc::munmap(addr, map_length).is_ok());
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn munmap(addr: usize, len: size_t) -> Result<(), Errno> {
    let len = len as usize;
    syscall2(SYS_MUNMAP, addr, len).map(drop)
}

/// Set protection on a region of memory.
///
/// ```
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let addr = nc::mmap(
///     0,
///     map_length,
///     nc::PROT_READ | nc::PROT_WRITE,
///     nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
///     -1,
///     0,
/// );
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// // Set the third page readonly. And we will run into SIGSEGV when updating it.
/// let ret = nc::mprotect(addr + 2 * nc::PAGE_SIZE, nc::PAGE_SIZE, nc::PROT_READ);
/// assert!(ret.is_ok());
///
/// assert!(nc::munmap(addr, map_length).is_ok());
/// ```
pub unsafe fn mprotect(addr: usize, len: size_t, prot: i32) -> Result<(), Errno> {
    let len = len as usize;
    let prot = prot as usize;
    syscall3(SYS_MPROTECT, addr, len, prot).map(drop)
}

/// Give advice about use of memory.
///
/// ```
/// // Initialize an anonymous mapping with 4 pages.
/// let map_length = 4 * nc::PAGE_SIZE;
/// let addr = nc::mmap(
///     0,
///     map_length,
///     nc::PROT_READ | nc::PROT_WRITE,
///     nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
///     -1,
///     0,
/// );
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// // Set the third page readonly. And we will run into SIGSEGV when updating it.
/// let ret = nc::madvise(addr + 2 * nc::PAGE_SIZE, nc::PAGE_SIZE, nc::MADV_RANDOM);
/// assert!(ret.is_ok());
///
/// assert!(nc::munmap(addr, map_length).is_ok());
/// ```
pub unsafe fn madvise(addr: usize, len: size_t, advice: i32) -> Result<(), Errno> {
    let len = len as usize;
    let advice = advice as usize;
    syscall3(SYS_MADVISE, addr, len, advice).map(drop)
}

/// Get list of supplementary group Ids.
///
/// ```
/// let mut groups = vec![];
/// let ret = nc::getgroups(0, &mut groups);
/// assert!(ret.is_ok());
/// let total_num = ret.unwrap();
/// groups.resize(total_num as usize, 0);
///
/// let ret = nc::getgroups(total_num, &mut groups);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(total_num));
/// ```
pub unsafe fn getgroups(size: i32, group_list: &mut [gid_t]) -> Result<i32, Errno> {
    let size = size as usize;
    let group_ptr = group_list.as_mut_ptr() as usize;
    syscall2(SYS_GETGROUPS, size, group_ptr).map(|ret| ret as i32)
}

/// Set list of supplementary group Ids.
///
/// ```
/// let list = [0, 1, 2];
/// let ret = nc::setgroups(&list);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setgroups(group_list: &[gid_t]) -> Result<(), Errno> {
    let group_len = group_list.len();
    let group_ptr = group_list.as_ptr() as usize;
    syscall2(SYS_SETGROUPS, group_len, group_ptr).map(drop)
}

/// Get the process group ID of the calling process.
///
/// ```
/// let pgroup = nc::getpgrp();
/// assert!(pgroup > 0);
/// ```
#[must_use]
pub unsafe fn getpgrp() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETPGRP).expect("getpgrp() failed") as pid_t
}

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
///
/// ```
/// let ret = nc::setpgid(nc::getpid(), 1);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let pgid = pgid as usize;
    syscall2(SYS_SETPGID, pid, pgid).map(drop)
}

/// Set value of an interval timer.
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

/// Start swapping to file/device.
///
/// ```
/// let filename = "/dev/sda-no-exist";
/// let ret = nc::swapon(filename);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn swapon<P: AsRef<Path>>(name: P) -> Result<(), Errno> {
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    syscall1(SYS_SWAPON, name_ptr).map(drop)
}

/// Get value of an interval timer.
pub unsafe fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    let which = which as usize;
    let curr_val_ptr = curr_val as *mut itimerval_t as usize;
    syscall2(SYS_GETITIMER, which, curr_val_ptr).map(drop)
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
///
/// ```
/// let path = "/tmp/nc-dup2-file";
/// let fd = nc::creat(path, 0o644);
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let newfd = 8;
/// assert!(nc::dup2(fd, newfd).is_ok());
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::close(newfd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn dup2(oldfd: i32, newfd: i32) -> Result<(), Errno> {
    let oldfd = oldfd as usize;
    let newfd = newfd as usize;
    syscall2(SYS_DUP2, oldfd, newfd).map(drop)
}

/// manipulate file descriptor.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let ret = nc::fcntl(fd, nc::F_DUPFD, 0);
/// assert!(ret.is_ok());
/// let fd2 = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::close(fd2).is_ok());
/// ```
pub unsafe fn fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
    let fd = fd as usize;
    let cmd = cmd as usize;
    syscall3(SYS_FCNTL, fd, cmd, arg).map(|ret| ret as i32)
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

/// Flush all modified in-core data refered by `fd` to disk.
///
/// ```
/// let path = "/tmp/nc-fsync";
/// let ret = nc::open(path, nc::O_CREAT | nc::O_WRONLY, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let buf = b"Hello, Rust";
/// let n_write = nc::write(fd, buf.as_ptr() as usize, buf.len());
/// assert_eq!(n_write, Ok(buf.len() as isize));
/// assert!(nc::fsync(fd).is_ok());
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn fsync(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FSYNC, fd).map(drop)
}

/// Set program scheduling priority.
///
/// ```
/// let ret = nc::setpriority(nc::PRIO_PROCESS, nc::getpid(), -19);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EACCES))
/// ```
pub unsafe fn setpriority(which: i32, who: i32, prio: i32) -> Result<(), Errno> {
    let which = which as usize;
    let who = who as usize;
    let prio = prio as usize;
    syscall3(SYS_SETPRIORITY, which, who, prio).map(drop)
}

/// Initialize a connection on a socket.
pub unsafe fn connect(sockfd: i32, addr: &sockaddr_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *const sockaddr_t as usize;
    let addrlen = addrlen as usize;
    syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen).map(drop)
}

/// Get program scheduling priority.
///
/// ```
/// let ret = nc::getpriority(nc::PRIO_PROCESS, nc::getpid());
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

/// Bind a name to a socket.
pub unsafe fn bind(sockfd: i32, addr: &sockaddr_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *const sockaddr_t as usize;
    let addrlen = addrlen as usize;
    syscall3(SYS_BIND, sockfd, addr_ptr, addrlen).map(drop)
}

/// Set options on sockets.
pub unsafe fn setsockopt(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: &sockaddr_t,
    optlen: socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let optname = optname as usize;
    let optval_ptr = optval as *const sockaddr_t as usize;
    let optlen = optlen as usize;
    syscall5(SYS_SETSOCKOPT, sockfd, level, optname, optval_ptr, optlen).map(drop)
}

/// Listen for connections on a socket.
pub unsafe fn listen(sockfd: i32, backlog: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let backlog = backlog as usize;
    syscall2(SYS_LISTEN, sockfd, backlog).map(drop)
}

/// Get time.
///
/// ```
/// let mut tv = nc::timeval_t::default();
/// let mut tz = nc::timezone_t::default();
/// let ret = nc::gettimeofday(&mut tv, &mut tz);
/// assert!(ret.is_ok());
/// assert!(tv.tv_sec > 1611380386);
/// ```
pub unsafe fn gettimeofday(timeval: &mut timeval_t, tz: &mut timezone_t) -> Result<(), Errno> {
    let timeval_ptr = timeval as *mut timeval_t as usize;
    let tz_ptr = tz as *mut timezone_t as usize;
    syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop)
}

/// Get resource usage.
///
/// ```
/// let mut usage = nc::rusage_t::default();
/// let ret = nc::getrusage(nc::RUSAGE_SELF, &mut usage);
/// assert!(ret.is_ok());
/// assert!(usage.ru_maxrss > 0);
/// assert_eq!(usage.ru_nswap, 0);
/// ```
pub unsafe fn getrusage(who: i32, usage: &mut rusage_t) -> Result<(), Errno> {
    let who = who as usize;
    let usage_ptr = usage as *mut rusage_t as usize;
    syscall2(SYS_GETRUSAGE, who, usage_ptr).map(drop)
}

/// Get options on sockets
pub unsafe fn getsockopt(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: &mut sockaddr_t,
    optlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let optname = optname as usize;
    let optval_ptr = optval as *mut sockaddr_t as usize;
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

/// Read from a file descriptor into multiple buffers.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
/// // TODO(Shaohua): Replace with as_mut_ptr()
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as usize,
///     });
/// }
/// let ret = nc::readv(fd, &mut iov);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn readv(fd: i32, iov: &mut [iovec_t]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let iov_ptr = iov.as_mut_ptr() as usize;
    let len = iov.len() as usize;
    syscall3(SYS_READV, fd, iov_ptr, len).map(|ret| ret as ssize_t)
}

/// Write to a file descriptor from multiple buffers.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as usize,
///     });
/// }
/// let ret = nc::readv(fd, &mut iov);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
///
/// let path_out = "/tmp/nc-writev";
/// let ret = nc::open(path_out, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::writev(fd, &iov);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path_out).is_ok());
/// ```
pub unsafe fn writev(fd: i32, iov: &[iovec_t]) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let iov_ptr = iov.as_ptr() as usize;
    let len = iov.len() as usize;
    syscall3(SYS_WRITEV, fd, iov_ptr, len).map(|ret| ret as ssize_t)
}

/// Set system time and timezone.
///
/// ```
/// let tv = nc::timeval_t {
///     tv_sec: 0,
///     tv_usec: 0,
/// };
/// let tz = nc::timezone_t::default();
/// let ret = nc::settimeofday(&tv, &tz);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn settimeofday(timeval: &timeval_t, tz: &timezone_t) -> Result<(), Errno> {
    let timeval_ptr = timeval as *const timeval_t as usize;
    let tz_ptr = tz as *const timezone_t as usize;
    syscall2(SYS_SETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop)
}

/// Change ownership of a file.
///
/// ```
/// let filename = "/tmp/nc-fchown";
/// let ret = nc::creat(filename, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::fchown(fd, 0, 0);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(filename).is_ok());
/// ```
pub unsafe fn fchown(fd: i32, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_FCHOWN, fd, user, group).map(drop)
}

/// Set real and effective user IDs of the calling process.
///
/// ```
/// let ret = nc::setreuid(0, 0);
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), Errno> {
    let ruid = ruid as usize;
    let euid = euid as usize;
    syscall2(SYS_SETREUID, ruid, euid).map(drop)
}

/// Set real and effective group IDs of the calling process.
///
/// ```
/// let ret = nc::setregid(0, 0);
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setregid(rgid: gid_t, egid: gid_t) -> Result<(), Errno> {
    let rgid = rgid as usize;
    let egid = egid as usize;
    syscall2(SYS_SETREGID, rgid, egid).map(drop)
}

/// Change name or location of a file.
///
/// ```
/// let path = "/tmp/nc-rename";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let new_path = "/tmp/nc-rename-new";
/// let ret = nc::rename(path, new_path);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(new_path).is_ok());
/// ```
pub unsafe fn rename<P: AsRef<Path>>(oldfilename: P, newfilename: P) -> Result<(), Errno> {
    let oldfilename = CString::new(oldfilename.as_ref());
    let oldfilename_ptr = oldfilename.as_ptr() as usize;
    let newfilename = CString::new(newfilename.as_ref());
    let newfilename_ptr = newfilename.as_ptr() as usize;
    syscall2(SYS_RENAME, oldfilename_ptr, newfilename_ptr).map(drop)
}

/// Apply or remove an advisory lock on an open file.
///
/// ```
/// let path = "/tmp/nc-flock";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::flock(fd, nc::LOCK_EX);
/// assert!(ret.is_ok());
/// let msg = "Hello, Rust";
/// let ret = nc::write(fd, msg.as_ptr() as usize, msg.len());
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// let ret = nc::flock(fd, nc::LOCK_UN);
/// assert!(ret.is_ok());
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn flock(fd: i32, operation: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    let operation = operation as usize;
    syscall2(SYS_FLOCK, fd, operation).map(drop)
}

/// Send a message on a socket.
pub unsafe fn sendto(
    sockfd: i32,
    buf: &[u8],
    len: size_t,
    flags: i32,
    dest_addr: &sockaddr_t,
    addrlen: socklen_t,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let len = len as usize;
    let flags = flags as usize;
    let dest_addr_ptr = dest_addr as *const sockaddr_t as usize;
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

/// Shutdown part of a full-duplex connection.
pub unsafe fn shutdown(sockfd: i32, how: i32) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let how = how as usize;
    syscall2(SYS_SHUTDOWN, sockfd, how).map(drop)
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

/// Create a directory.
///
/// ```
/// let path = "/tmp/nc-mkdir";
/// let ret = nc::mkdir(path, 0o755);
/// assert!(ret.is_ok());
/// assert!(nc::rmdir(path).is_ok());
/// ```
pub unsafe fn mkdir<P: AsRef<Path>>(filename: P, mode: mode_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall2(SYS_MKDIR, filename_ptr, mode).map(drop)
}

/// Delete a directory.
///
/// ```
/// let path = "/tmp/nc-rmdir";
/// let ret = nc::mkdir(path, 0o755);
/// assert!(ret.is_ok());
/// assert!(nc::rmdir(path).is_ok());
/// ```
pub unsafe fn rmdir<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_RMDIR, filename_ptr).map(drop)
}

/// Change file last access and modification time.
///
/// ```
/// let path = "/tmp/nc-utimes";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
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
/// let ret = nc::utimes(path, &times);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn utimes<P: AsRef<Path>>(filename: P, times: &[timeval_t; 2]) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let times_ptr = times.as_ptr() as usize;
    syscall2(SYS_UTIMES, filename_ptr, times_ptr).map(drop)
}

/// Create a new session if the calling process is not a process group leader.
///
/// ```
/// let ret = nc::setsid();
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(nc::getpid()));
/// ```
pub unsafe fn setsid() -> Result<pid_t, Errno> {
    syscall0(SYS_SETSID).map(|ret| ret as pid_t)
}

/// Manipulate disk quotes.
pub unsafe fn quotactl<P: AsRef<Path>>(
    path: P,
    cmd: i32,
    uid: uid_t,
    addr: usize,
) -> Result<(), Errno> {
    let cmd = cmd as usize;
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let uid = uid as usize;
    syscall4(SYS_QUOTACTL, path_ptr, cmd, uid, addr).map(drop)
}

/// Set the group ID of the calling process to `gid`.
///
/// ```
/// let ret = nc::setgid(0);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setgid(gid: gid_t) -> Result<(), Errno> {
    let gid = gid as usize;
    syscall1(SYS_SETGID, gid).map(drop)
}

/// Get resource limit.
///
/// ```
/// let mut rlimit = nc::rlimit_t::default();
/// let ret = nc::getrlimit(nc::RLIMIT_NOFILE, &mut rlimit);
/// assert!(ret.is_ok());
/// assert!(rlimit.rlim_cur > 0);
/// assert!(rlimit.rlim_max > 0);
/// ```
pub unsafe fn getrlimit(resource: i32, rlim: &mut rlimit_t) -> Result<(), Errno> {
    let resource = resource as usize;
    let rlim_ptr = rlim as *mut rlimit_t as usize;
    syscall2(SYS_GETRLIMIT, resource, rlim_ptr).map(drop)
}

/// Set resource limit.
///
/// ```
/// let rlimit = nc::rlimit_t {
///     rlim_cur: 128,
///     rlim_max: 128,
/// };
/// let ret = nc::setrlimit(nc::RLIMIT_NOFILE, &rlimit);
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setrlimit(resource: i32, rlimit: &rlimit_t) -> Result<(), Errno> {
    let resource = resource as usize;
    let rlimit_ptr = rlimit as *const rlimit_t as usize;
    syscall2(SYS_SETRLIMIT, resource, rlimit_ptr).map(drop)
}

/// Lock memory.
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let ret = nc::mlock(passwd_buf.as_ptr() as usize, passwd_buf.len());
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlock(addr: usize, len: size_t) -> Result<(), Errno> {
    let len = len as usize;
    syscall2(SYS_MLOCK, addr, len).map(drop)
}

/// Unlock memory.
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let addr = passwd_buf.as_ptr() as usize;
/// let ret = nc::mlock(addr, passwd_buf.len());
/// for i in 0..passwd_buf.len() {
///   passwd_buf[i] = i as u8;
/// }
/// assert!(ret.is_ok());
/// let ret = nc::munlock(addr, passwd_buf.len());
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlock(addr: usize, len: size_t) -> Result<(), Errno> {
    let len = len as usize;
    syscall2(SYS_MUNLOCK, addr, len).map(drop)
}

/// Returns the PGID(process group ID) of the process specified by `pid`.
///
/// ```
/// let ppid = nc::getppid();
/// let pgid = nc::getpgid(ppid);
/// assert!(pgid.is_ok());
/// ```
pub unsafe fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    syscall1(SYS_GETPGID, pid).map(|ret| ret as pid_t)
}

/// Wait for some event on file descriptors.
pub unsafe fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<(), Errno> {
    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len() as usize;
    let timeout = timeout as usize;
    syscall3(SYS_POLL, fds_ptr, nfds, timeout).map(drop)
}

/// Get time of specific clock.
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = nc::clock_gettime(nc::CLOCK_REALTIME_COARSE, &mut tp);
/// assert!(ret.is_ok());
/// assert!(tp.tv_sec > 0);
/// ```
pub unsafe fn clock_gettime(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *mut timespec_t as usize;
    syscall2(SYS_CLOCK_GETTIME, which_clock, tp_ptr).map(drop)
}

/// Set time of specific clock.
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = nc::clock_gettime(nc::CLOCK_REALTIME, &mut tp);
/// assert!(ret.is_ok());
/// assert!(tp.tv_sec > 0);
/// let ret = nc::clock_settime(nc::CLOCK_REALTIME, &tp);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn clock_settime(which_clock: clockid_t, tp: &timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *const timespec_t as usize;
    syscall2(SYS_CLOCK_SETTIME, which_clock, tp_ptr).map(drop)
}

/// Get resolution(precision) of the specific clock.
///
/// ```
/// let mut tp = nc::timespec_t::default();
/// let ret = nc::clock_getres(nc::CLOCK_BOOTTIME, &mut tp);
/// assert!(ret.is_ok());
/// assert!(tp.tv_nsec > 0);
/// ```
pub unsafe fn clock_getres(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    let which_clock = which_clock as usize;
    let tp_ptr = tp as *mut timespec_t as usize;
    syscall2(SYS_CLOCK_GETRES, which_clock, tp_ptr).map(drop)
}

/// High resolution sleep.
///
/// ```
/// let t = nc::timespec_t {
///     tv_sec: 1,
///     tv_nsec: 0,
/// };
/// assert!(nc::nanosleep(&t, None).is_ok());
/// ```
pub unsafe fn nanosleep(req: &timespec_t, rem: Option<&mut timespec_t>) -> Result<(), Errno> {
    let req_ptr = req as *const timespec_t as usize;
    let rem_ptr = rem.map_or(0, |rem| rem as *mut timespec_t as usize);
    syscall2(SYS_NANOSLEEP, req_ptr, rem_ptr).map(drop)
}

/// High resolution sleep with a specific clock.
///
/// ```
/// let t = nc::timespec_t {
///     tv_sec: 1,
///     tv_nsec: 0,
/// };
/// let mut rem = nc::timespec_t::default();
/// assert!(nc::clock_nanosleep(nc::CLOCK_MONOTONIC, 0, &t, &mut rem).is_ok());
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

/// Change ownership of a file. Does not deference symbolic link.
///
/// ```
/// let filename = "/tmp/nc-lchown";
/// let ret = nc::creat(filename, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let ret = nc::lchown(filename, 0, 0);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// assert!(nc::unlink(filename).is_ok());
/// ```
pub unsafe fn lchown<P: AsRef<Path>>(filename: P, user: uid_t, group: gid_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let user = user as usize;
    let group = group as usize;
    syscall3(SYS_LCHOWN, filename_ptr, user, group).map(drop)
}

/// Read from a file descriptor without changing file offset.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as usize,
///     });
/// }
/// let iov_len = iov.len();
/// let ret = nc::preadv(fd, &mut iov, 0, iov_len - 1);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
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

/// Write to a file descriptor without changing file offset.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [[0_u8; 64]; 4];
/// let capacity = 4 * 64;
/// let mut iov = Vec::with_capacity(buf.len());
/// for ref mut item in (&mut buf).iter() {
///     iov.push(nc::iovec_t {
///         iov_len: item.len(),
///         iov_base: item.as_ptr() as usize,
///     });
/// }
/// let ret = nc::readv(fd, &mut iov);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
///
/// let path_out = "/tmp/nc-pwritev";
/// let ret = nc::open(path_out, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::pwritev(fd, &iov, 0, iov.len() - 1);
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(capacity as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path_out).is_ok());
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

/// Get session Id.
///
/// ```
/// let ppid = nc::getppid();
/// let sid = nc::getsid(ppid);
/// assert!(sid > 0);
/// ```
#[must_use]
pub unsafe fn getsid(pid: pid_t) -> pid_t {
    let pid = pid as usize;
    // This function is always successful.
    syscall1(SYS_GETSID, pid).expect("getsid() failed") as pid_t
}

/// Set real, effective and saved user Ids of the calling process.
///
/// ```
/// let ret = nc::setresuid(0, 0, 0);
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<(), Errno> {
    let ruid = ruid as usize;
    let euid = euid as usize;
    let suid = suid as usize;
    syscall3(SYS_SETRESUID, ruid, euid, suid).map(drop)
}

/// Set real, effective and saved group Ids of the calling process.
///
/// ```
/// let ret = nc::setresgid(0, 0, 0);
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<(), Errno> {
    let rgid = rgid as usize;
    let egid = egid as usize;
    let sgid = sgid as usize;
    syscall3(SYS_SETRESGID, rgid, egid, sgid).map(drop)
}

/// Lock memory.
///
/// ```
/// let ret = nc::mlockall(nc::MCL_CURRENT);
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlockall(flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    syscall1(SYS_MLOCKALL, flags).map(drop)
}

/// Unlock memory.
///
/// ```
/// let ret = nc::mlockall(nc::MCL_CURRENT);
/// assert!(ret.is_ok());
/// let ret = nc::munlockall();
/// assert!(ret.is_ok());
/// ```
pub unsafe fn munlockall() -> Result<(), Errno> {
    syscall0(SYS_MUNLOCKALL).map(drop)
}

/// Set scheduling paramters.
///
/// ```
/// // This call always returns error because default scheduler is `SCHED_NORMAL`.
/// // We shall call `sched_setscheduler()` and change to realtime policy
/// // like `SCHED_RR` or `SCHED_FIFO`.
/// let sched_param = nc::sched_param_t { sched_priority: 12 };
/// let ret = nc::sched_setparam(0, &sched_param);
/// assert_eq!(ret, Err(nc::EINVAL));
/// ```
pub unsafe fn sched_setparam(pid: pid_t, param: &sched_param_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let param_ptr = param as *const sched_param_t as usize;
    syscall2(SYS_SCHED_SETPARAM, pid, param_ptr).map(drop)
}

/// Get scheduling paramters.
///
/// ```
/// let mut param = nc::sched_param_t::default();
/// let ret = nc::sched_getparam(0, &mut param);
/// assert!(ret.is_ok());
/// assert_eq!(param.sched_priority, 0);
/// ```
pub unsafe fn sched_getparam(pid: pid_t, param: &mut sched_param_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let param_ptr = param as *mut sched_param_t as usize;
    syscall2(SYS_SCHED_GETPARAM, pid, param_ptr).map(drop)
}

/// Set scheduling parameter.
///
/// ```
/// let sched_param = nc::sched_param_t { sched_priority: 12 };
/// let ret = nc::sched_setscheduler(0, nc::SCHED_RR, &sched_param);
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

/// Get scheduling parameter.
///
/// ```
/// let ret = nc::sched_getscheduler(0);
/// assert_eq!(ret, Ok(nc::SCHED_OTHER));
/// ```
pub unsafe fn sched_getscheduler(pid: pid_t) -> Result<i32, Errno> {
    let pid = pid as usize;
    syscall1(SYS_SCHED_GETSCHEDULER, pid).map(|ret| ret as i32)
}

/// Yield the processor.
///
/// ```
/// assert!(nc::sched_yield().is_ok());
/// ```
pub unsafe fn sched_yield() -> Result<(), Errno> {
    syscall0(SYS_SCHED_YIELD).map(drop)
}

/// Get static priority max value.
///
/// ```
/// let ret = nc::sched_get_priority_max(nc::SCHED_RR);
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
/// ```
/// let ret = nc::sched_get_priority_min(nc::SCHED_RR);
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
/// ```
/// let mut ts = nc::timespec_t::default();
/// let ret = nc::sched_rr_get_interval(0, &mut ts);
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sched_rr_get_interval(pid: pid_t, interval: &mut timespec_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let interval_ptr = interval as *mut timespec_t as usize;
    syscall2(SYS_SCHED_RR_GET_INTERVAL, pid, interval_ptr).map(drop)
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

/// Wait for a signal.
pub unsafe fn sigsuspend(mask: &old_sigset_t) -> Result<(), Errno> {
    let mask_ptr = mask as *const old_sigset_t as usize;
    syscall1(SYS_SIGSUSPEND, mask_ptr).map(drop)
}

/// Examine pending signals.
pub unsafe fn sigpending(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = set as *mut sigset_t as usize;
    syscall1(SYS_SIGPENDING, set_ptr).map(drop)
}

/// Get real, effect and saved user ID.
///
/// ```
/// let mut ruid = 0;
/// let mut euid = 0;
/// let mut suid = 0;
/// let ret = nc::getresuid(&mut ruid, &mut euid, &mut suid);
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

/// Get real, effect and saved group ID.
///
/// ```
/// let mut rgid = 0;
/// let mut egid = 0;
/// let mut sgid = 0;
/// let ret = nc::getresgid(&mut rgid, &mut egid, &mut sgid);
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
    let count = count as usize;
    syscall4(SYS_SENDFILE, out_fd, in_fd, offset_ptr, count).map(|ret| ret as ssize_t)
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

/// Return from signal handler and cleanup stack frame.
/// Never returns.
pub unsafe fn sigreturn() {
    let _ = syscall0(SYS_SIGRETURN);
}

/// Handle `{get,set,swap}_context` operations
pub unsafe fn swapcontext() {
    core::unimplemented!();
    //pub unsafe fn swapcontext(old_ctx: &mut ucontext_t, new_ctx: &mut ucontext_t, ctx_size: isize,) -> Result<(), Errno> {}
    // syscall0(SYS_SWAPCONTEXT);
    //
    //        let old_ctx_ptr = old_ctx as *mut ucontext_t as usize;
    //        let new_ctx_ptr = new_ctx as *mut ucontext_t as usize;
    //        let ctx_size = ctx_size as usize;
    //        syscall3(SYS_SWAPCONTEXT, old_ctx_ptr, new_ctx_ptr, ctx_size).map(drop)
    //    }
}

/// Stop swapping to file/device.
///
/// ```
/// let filename = "/dev/sda-no-exist";
/// let ret = nc::swapoff(filename);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn swapoff<P: AsRef<Path>>(filename: P) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall1(SYS_SWAPOFF, filename_ptr).map(drop)
}

/// Map files or devices into memory.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
///
/// let mut sb = nc::stat_t::default();
/// let ret = nc::fstat(fd, &mut sb);
/// assert!(ret.is_ok());
///
/// let offset: usize = 0;
/// let length: usize = sb.st_size as usize - offset;
/// // Offset for mmap must be page aligned.
/// let pa_offset: usize = offset & !(nc::PAGE_SIZE - 1);
/// let map_length = length + offset - pa_offset;
///
/// let addr = nc::mmap(
///     0, // 0 as NULL
///     map_length,
///     nc::PROT_READ,
///     nc::MAP_PRIVATE,
///     fd,
///     pa_offset as nc::off_t,
/// );
/// assert!(addr.is_ok());
/// let addr = addr.unwrap();
///
/// let n_write = nc::write(1, addr + offset - pa_offset, length);
/// assert!(n_write.is_ok());
/// assert_eq!(n_write, Ok(length as nc::ssize_t));
/// assert!(nc::munmap(addr, map_length).is_ok());
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn mmap(
    start: usize,
    len: size_t,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: off_t,
) -> Result<usize, Errno> {
    let len = len as usize;
    let prot = prot as usize;
    let flags = flags as usize;
    let fd = fd as usize;
    let offset = offset as usize;
    syscall6(SYS_MMAP, start, len, prot, flags, fd, offset)
}

/// Reposition file offset.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::lseek(fd, 42, nc::SEEK_SET);
/// assert!(ret.is_ok());
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn lseek(fd: i32, offset: off_t, whence: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    let offset = offset as usize;
    let whence = whence as usize;
    syscall3(SYS_LSEEK, fd, offset, whence).map(drop)
}

/// Truncate a file to a specified length.
///
/// ```
/// let path = "/tmp/nc-truncate";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let ret = nc::truncate(path, 64 * 1024);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn truncate<P: AsRef<Path>>(filename: P, length: off_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let length = length as usize;
    syscall2(SYS_TRUNCATE, filename_ptr, length).map(drop)
}

/// Truncate an opened file to a specified length.
///
/// ```
/// let path = "/tmp/nc-ftruncate";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let ret = nc::ftruncate(fd, 64 * 1024);
/// assert!(ret.is_ok());
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn ftruncate(fd: i32, length: off_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let length = length as usize;
    syscall2(SYS_FTRUNCATE, fd, length).map(drop)
}

/// Check user's permission for a file.
///
/// ```
/// assert!(nc::faccessat(nc::AT_FDCWD, "/etc/passwd", nc::F_OK).is_ok());
/// ```
pub unsafe fn faccessat<P: AsRef<Path>>(dfd: i32, filename: P, mode: i32) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall3(SYS_FACCESSAT, dfd, filename_ptr, mode).map(drop)
}

/// Change permissions of a file.
///
/// ```
/// let filename = "/tmp/nc-fchmodat";
/// let ret = nc::creat(filename, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::fchmodat(nc::AT_FDCWD, filename, 0o600).is_ok());
/// assert!(nc::unlink(filename).is_ok());
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
/// ```
/// let filename = "/tmp/nc-fchown";
/// let ret = nc::creat(filename, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let ret = nc::fchownat(nc::AT_FDCWD, filename, 0, 0, 0);
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EPERM));
/// assert!(nc::unlink(filename).is_ok());
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

/// Change timestamp of a file relative to a directory file discriptor.
///
/// ```
/// let path = "/tmp/nc-futimesat";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
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
/// let ret = nc::futimesat(nc::AT_FDCWD, path, &times);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(path).is_ok());
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

/// Make a new name for a file.
///
/// ```
/// let old_filename = "/tmp/nc-linkat-src";
/// let ret = nc::open(old_filename, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let new_filename = "/tmp/nc-linkat-dst";
/// let flags = nc::AT_SYMLINK_FOLLOW;
/// assert!(nc::linkat(nc::AT_FDCWD, old_filename, nc::AT_FDCWD,  new_filename, flags).is_ok());
/// assert!(nc::unlink(old_filename).is_ok());
/// assert!(nc::unlink(new_filename).is_ok());
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

/// Create a directory.
///
/// ```
/// let path = "/tmp/nc-mkdir";
/// let ret = nc::mkdirat(nc::AT_FDCWD, path, 0o755);
/// assert!(ret.is_ok());
/// assert!(nc::rmdir(path).is_ok());
/// ```
pub unsafe fn mkdirat<P: AsRef<Path>>(dirfd: i32, filename: P, mode: mode_t) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let mode = mode as usize;
    syscall3(SYS_MKDIRAT, dirfd, filename_ptr, mode).map(drop)
}

/// Open and possibly create a file within a directory.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
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

/// Read value of a symbolic link.
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-readlinkat";
/// let ret = nc::symlink(oldname, newname);
/// assert!(ret.is_ok());
/// let mut buf = [0_u8; nc::PATH_MAX as usize];
/// let buf_len = buf.len();
/// let ret = nc::readlinkat(nc::AT_FDCWD, newname, &mut buf, buf_len);
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap() as usize;
/// assert_eq!(n_read, oldname.len());
/// assert_eq!(oldname.as_bytes(), &buf[0..n_read]);
/// assert!(nc::unlink(newname).is_ok());
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

/// Change name or location of a file.
///
/// ```
/// let path = "/tmp/nc-renameat";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// let new_path = "/tmp/nc-renameat-new";
/// let ret = nc::renameat(nc::AT_FDCWD, path, nc::AT_FDCWD, new_path);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(new_path).is_ok());
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

/// Make a new name for a file.
///
/// ```
/// let oldname = "/etc/passwd";
/// let newname = "/tmp/nc-symlinkat";
/// let ret = nc::symlinkat(oldname, nc::AT_FDCWD, newname);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(newname).is_ok());
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

/// Delete a name and possibly the file it refers to.
///
/// ```
/// let path = "/tmp/nc-unlinkat";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// // /tmp folder is not empty, so this call always returns error.
/// assert!(nc::unlinkat(nc::AT_FDCWD, path, nc::AT_REMOVEDIR).is_err());
/// assert!(nc::unlinkat(nc::AT_FDCWD, path, 0).is_ok());
/// ```
pub unsafe fn unlinkat<P: AsRef<Path>>(dfd: i32, filename: P, flag: i32) -> Result<(), Errno> {
    let dfd = dfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flag = flag as usize;
    syscall3(SYS_UNLINKAT, dfd, filename_ptr, flag).map(drop)
}

/// Accept a connection on a socket.
pub unsafe fn accept4(
    sockfd: i32,
    addr: &mut sockaddr_t,
    addrlen: &mut socklen_t,
    flags: i32,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *mut sockaddr_t as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    let flags = flags as usize;
    syscall4(SYS_ACCEPT4, sockfd, addr_ptr, addrlen_ptr, flags).map(drop)
}

/// Create a pipe.
///
/// ```
/// let mut fds = [-1_i32, 2];
/// let ret = nc::pipe2(&mut fds, nc::O_CLOEXEC | nc::O_NONBLOCK);
/// assert!(ret.is_ok());
/// assert!(nc::close(fds[0]).is_ok());
/// assert!(nc::close(fds[1]).is_ok());
/// ```
pub unsafe fn pipe2(pipefd: &mut [i32; 2], flags: i32) -> Result<(), Errno> {
    let pipefd_ptr = pipefd.as_mut_ptr() as usize;
    let flags = flags as usize;
    syscall2(SYS_PIPE2, pipefd_ptr, flags).map(drop)
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
    let sigsetsize = sigsetsize as usize;
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

/// Change time timestamps with nanosecond precision.
///
/// ```
/// let path = "/tmp/nc-utimesat";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
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
/// let ret = nc::utimensat(nc::AT_FDCWD, path, &times, flags);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(path).is_ok());
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

/// Flush all modified in-core data (exclude metadata) refered by `fd` to disk.
///
/// ```
/// let path = "/tmp/nc-fdatasync";
/// let ret = nc::open(path, nc::O_WRONLY | nc::O_CREAT, 0o644);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let msg = b"Hello, Rust";
/// let ret = nc::write(fd, msg.as_ptr() as usize, msg.len());
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
/// assert!(nc::close(fd).is_ok());
/// assert!(nc::unlink(path).is_ok());
/// ```
pub unsafe fn fdatasync(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_FDATASYNC, fd).map(drop)
}

/// Get file status about a file descriptor.
///
/// ```
/// let path = "/tmp";
/// // Open folder directly.
/// let fd = nc::open(path, nc::O_PATH, 0);
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut stat = nc::stat_t::default();
/// let ret = nc::fstat(fd, &mut stat);
/// assert!(ret.is_ok());
/// // Check fd is a directory.
/// assert_eq!((stat.st_mode & nc::S_IFMT), nc::S_IFDIR);
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn fstat(fd: i32, statbuf: &mut stat_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let statbuf_ptr = statbuf as *mut stat_t as usize;
    syscall2(SYS_FSTAT, fd, statbuf_ptr).map(drop)
}

/// Get file status.
///
/// ```
/// let path = "/etc/passwd";
/// let mut stat = nc::stat_t::default();
/// let ret = nc::fstatat(nc::AT_FDCWD, path, &mut stat, nc::AT_SYMLINK_NOFOLLOW);
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
/// ```
/// let path = "/usr";
/// let mut statfs = nc::statfs_t::default();
/// let ret = nc::statfs(path, &mut statfs);
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

/// Get filesystem statistics.
///
/// ```
/// let path = "/usr";
/// // Open folder directly.
/// let fd = nc::open(path, nc::O_PATH, 0);
/// assert!(fd.is_ok());
/// let fd = fd.unwrap();
/// let mut statfs = nc::statfs_t::default();
/// let ret = nc::fstatfs(fd, &mut statfs);
/// assert!(ret.is_ok());
/// assert!(statfs.f_bfree > 0);
/// assert!(statfs.f_bavail > 0);
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn fstatfs(fd: i32, buf: &mut statfs_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let buf_ptr = buf as *mut statfs_t as usize;
    syscall2(SYS_FSTATFS, fd, buf_ptr).map(drop)
}

/// Create a special or ordinary file.
///
/// ```
/// let path = "/tmp/nc-mknodat";
/// // Create a named pipe.
/// let ret = nc::mknodat(nc::AT_FDCWD, path, nc::S_IFIFO | nc::S_IRUSR | nc::S_IWUSR, 0);
/// assert!(ret.is_ok());
/// assert!(nc::unlink(path).is_ok());
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

/// Obtain a series of random bytes.
///
/// ```
/// let mut buf = [0_u8; 32];
/// let buf_len = buf.len();
/// let ret = nc::getrandom(&mut buf, buf_len, 0);
/// assert!(ret.is_ok());
/// let size = ret.unwrap() as usize;
/// assert!(size <= buf_len);
/// ```
pub unsafe fn getrandom(buf: &mut [u8], buf_len: usize, flags: u32) -> Result<ssize_t, Errno> {
    let buf_ptr = buf.as_mut_ptr() as usize;
    let flags = flags as usize;
    syscall3(SYS_GETRANDOM, buf_ptr, buf_len, flags).map(|ret| ret as ssize_t)
}

pub unsafe fn abort2() {
    core::unimplemented!();
    // syscall0(SYS_ABORT2);
}

pub unsafe fn adjtime() {
    core::unimplemented!();
    // syscall0(SYS_ADJTIME);
}

pub unsafe fn aio_cancel() {
    core::unimplemented!();
    // syscall0(SYS_AIO_CANCEL);
}

pub unsafe fn aio_error() {
    core::unimplemented!();
    // syscall0(SYS_AIO_ERROR);
}

pub unsafe fn aio_fsync() {
    core::unimplemented!();
    // syscall0(SYS_AIO_FSYNC);
}

pub unsafe fn aio_mlock() {
    core::unimplemented!();
    // syscall0(SYS_AIO_MLOCK);
}

pub unsafe fn aio_read() {
    core::unimplemented!();
    // syscall0(SYS_AIO_READ);
}

pub unsafe fn aio_return() {
    core::unimplemented!();
    // syscall0(SYS_AIO_RETURN);
}

pub unsafe fn aio_suspend() {
    core::unimplemented!();
    // syscall0(SYS_AIO_SUSPEND);
}

pub unsafe fn aio_waitcomplete() {
    core::unimplemented!();
    // syscall0(SYS_AIO_WAITCOMPLETE);
}

pub unsafe fn aio_write() {
    core::unimplemented!();
    // syscall0(SYS_AIO_WRITE);
}

pub unsafe fn audit() {
    core::unimplemented!();
    // syscall0(SYS_AUDIT);
}

pub unsafe fn auditctl() {
    core::unimplemented!();
    // syscall0(SYS_AUDITCTL);
}

pub unsafe fn auditon() {
    core::unimplemented!();
    // syscall0(SYS_AUDITON);
}

pub unsafe fn bindat() {
    core::unimplemented!();
    // syscall0(SYS_BINDAT);
}

pub unsafe fn r#break() {
    core::unimplemented!();
    // syscall0(SYS_BREAK);
}

pub unsafe fn cap_enter() {
    core::unimplemented!();
    // syscall0(SYS_CAP_ENTER);
}

pub unsafe fn cap_fcntls_get() {
    core::unimplemented!();
    // syscall0(SYS_CAP_FCNTLS_GET);
}

pub unsafe fn cap_fcntls_limit() {
    core::unimplemented!();
    // syscall0(SYS_CAP_FCNTLS_LIMIT);
}

pub unsafe fn cap_getmode() {
    core::unimplemented!();
    // syscall0(SYS_CAP_GETMODE);
}

pub unsafe fn cap_ioctls_get() {
    core::unimplemented!();
    // syscall0(SYS_CAP_IOCTLS_GET);
}

pub unsafe fn cap_ioctls_limit() {
    core::unimplemented!();
    // syscall0(SYS_CAP_IOCTLS_LIMIT);
}

pub unsafe fn cap_rights_limit() {
    core::unimplemented!();
    // syscall0(SYS_CAP_RIGHTS_LIMIT);
}

pub unsafe fn chflags() {
    core::unimplemented!();
    // syscall0(SYS_CHFLAGS);
}

pub unsafe fn chflagsat() {
    core::unimplemented!();
    // syscall0(SYS_CHFLAGSAT);
}

pub unsafe fn clock_getcpuclockid2() {
    core::unimplemented!();
    // syscall0(SYS_CLOCK_GETCPUCLOCKID2);
}

pub unsafe fn closefrom() {
    core::unimplemented!();
    // syscall0(SYS_CLOSEFROM);
}

pub unsafe fn connectat() {
    core::unimplemented!();
    // syscall0(SYS_CONNECTAT);
}

pub unsafe fn cpuset() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET);
}

pub unsafe fn cpuset_getaffinity() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_GETAFFINITY);
}

pub unsafe fn cpuset_getdomain() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_GETDOMAIN);
}

pub unsafe fn cpuset_getid() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_GETID);
}

pub unsafe fn cpuset_setaffinity() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_SETAFFINITY);
}

pub unsafe fn cpuset_setdomain() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_SETDOMAIN);
}

pub unsafe fn cpuset_setid() {
    core::unimplemented!();
    // syscall0(SYS_CPUSET_SETID);
}

pub unsafe fn eaccess() {
    core::unimplemented!();
    // syscall0(SYS_EACCESS);
}

pub unsafe fn extattrctl() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTRCTL);
}

pub unsafe fn extattr_delete_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_FD);
}

pub unsafe fn extattr_delete_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_FILE);
}

pub unsafe fn extattr_delete_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_LINK);
}

pub unsafe fn extattr_get_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_FD);
}

pub unsafe fn extattr_get_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_FILE);
}

pub unsafe fn extattr_get_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_LINK);
}

pub unsafe fn extattr_list_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_FD);
}

pub unsafe fn extattr_list_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_FILE);
}

pub unsafe fn extattr_list_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_LINK);
}

pub unsafe fn extattr_set_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_FD);
}

pub unsafe fn extattr_set_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_FILE);
}

pub unsafe fn extattr_set_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_LINK);
}

pub unsafe fn fchflags() {
    core::unimplemented!();
    // syscall0(SYS_FCHFLAGS);
}

pub unsafe fn fchmod() {
    core::unimplemented!();
    // syscall0(SYS_FCHMOD);
}

pub unsafe fn fexecve() {
    core::unimplemented!();
    // syscall0(SYS_FEXECVE);
}

pub unsafe fn ffclock_getcounter() {
    core::unimplemented!();
    // syscall0(SYS_FFCLOCK_GETCOUNTER);
}

pub unsafe fn ffclock_getestimate() {
    core::unimplemented!();
    // syscall0(SYS_FFCLOCK_GETESTIMATE);
}

pub unsafe fn ffclock_setestimate() {
    core::unimplemented!();
    // syscall0(SYS_FFCLOCK_SETESTIMATE);
}

pub unsafe fn fhlink() {
    core::unimplemented!();
    // syscall0(SYS_FHLINK);
}

pub unsafe fn fhlinkat() {
    core::unimplemented!();
    // syscall0(SYS_FHLINKAT);
}

pub unsafe fn fhopen() {
    core::unimplemented!();
    // syscall0(SYS_FHOPEN);
}

pub unsafe fn fhreadlink() {
    core::unimplemented!();
    // syscall0(SYS_FHREADLINK);
}

pub unsafe fn fhstat() {
    core::unimplemented!();
    // syscall0(SYS_FHSTAT);
}

pub unsafe fn fhstatfs() {
    core::unimplemented!();
    // syscall0(SYS_FHSTATFS);
}

pub unsafe fn fpathconf() {
    core::unimplemented!();
    // syscall0(SYS_FPATHCONF);
}

pub unsafe fn futimens() {
    core::unimplemented!();
    // syscall0(SYS_FUTIMENS);
}

pub unsafe fn futimes() {
    core::unimplemented!();
    // syscall0(SYS_FUTIMES);
}

pub unsafe fn getaudit() {
    core::unimplemented!();
    // syscall0(SYS_GETAUDIT);
}

pub unsafe fn getaudit_addr() {
    core::unimplemented!();
    // syscall0(SYS_GETAUDIT_ADDR);
}

pub unsafe fn getauid() {
    core::unimplemented!();
    // syscall0(SYS_GETAUID);
}

pub unsafe fn getcontext() {
    core::unimplemented!();
    // syscall0(SYS_GETCONTEXT);
}

pub unsafe fn getdirentries() {
    core::unimplemented!();
    // syscall0(SYS_GETDIRENTRIES);
}

pub unsafe fn getdtablesize() {
    core::unimplemented!();
    // syscall0(SYS_GETDTABLESIZE);
}

pub unsafe fn getfh() {
    core::unimplemented!();
    // syscall0(SYS_GETFH);
}

pub unsafe fn getfhat() {
    core::unimplemented!();
    // syscall0(SYS_GETFHAT);
}

pub unsafe fn getfsstat() {
    core::unimplemented!();
    // syscall0(SYS_GETFSSTAT);
}

pub unsafe fn getlogin() {
    core::unimplemented!();
    // syscall0(SYS_GETLOGIN);
}

pub unsafe fn getloginclass() {
    core::unimplemented!();
    // syscall0(SYS_GETLOGINCLASS);
}

pub unsafe fn issetugid() {
    core::unimplemented!();
    // syscall0(SYS_ISSETUGID);
}

pub unsafe fn jail() {
    core::unimplemented!();
    // syscall0(SYS_JAIL);
}

pub unsafe fn jail_attach() {
    core::unimplemented!();
    // syscall0(SYS_JAIL_ATTACH);
}

pub unsafe fn jail_get() {
    core::unimplemented!();
    // syscall0(SYS_JAIL_GET);
}

pub unsafe fn jail_remove() {
    core::unimplemented!();
    // syscall0(SYS_JAIL_REMOVE);
}

pub unsafe fn jail_set() {
    core::unimplemented!();
    // syscall0(SYS_JAIL_SET);
}

pub unsafe fn kenv() {
    core::unimplemented!();
    // syscall0(SYS_KENV);
}

pub unsafe fn kevent() {
    core::unimplemented!();
    // syscall0(SYS_KEVENT);
}

pub unsafe fn kldfind() {
    core::unimplemented!();
    // syscall0(SYS_KLDFIND);
}

pub unsafe fn kldfirstmod() {
    core::unimplemented!();
    // syscall0(SYS_KLDFIRSTMOD);
}

pub unsafe fn kldload() {
    core::unimplemented!();
    // syscall0(SYS_KLDLOAD);
}

pub unsafe fn kldnext() {
    core::unimplemented!();
    // syscall0(SYS_KLDNEXT);
}

pub unsafe fn kldstat() {
    core::unimplemented!();
    // syscall0(SYS_KLDSTAT);
}

pub unsafe fn kldsym() {
    core::unimplemented!();
    // syscall0(SYS_KLDSYM);
}

pub unsafe fn kldunload() {
    core::unimplemented!();
    // syscall0(SYS_KLDUNLOAD);
}

pub unsafe fn kldunloadf() {
    core::unimplemented!();
    // syscall0(SYS_KLDUNLOADF);
}

pub unsafe fn kqueue() {
    core::unimplemented!();
    // syscall0(SYS_KQUEUE);
}

pub unsafe fn ktimer_create() {
    core::unimplemented!();
    // syscall0(SYS_KTIMER_CREATE);
}

pub unsafe fn ktimer_delete() {
    core::unimplemented!();
    // syscall0(SYS_KTIMER_DELETE);
}

pub unsafe fn ktimer_getoverrun() {
    core::unimplemented!();
    // syscall0(SYS_KTIMER_GETOVERRUN);
}

pub unsafe fn ktimer_gettime() {
    core::unimplemented!();
    // syscall0(SYS_KTIMER_GETTIME);
}

pub unsafe fn ktimer_settime() {
    core::unimplemented!();
    // syscall0(SYS_KTIMER_SETTIME);
}

pub unsafe fn ktrace() {
    core::unimplemented!();
    // syscall0(SYS_KTRACE);
}

pub unsafe fn lchflags() {
    core::unimplemented!();
    // syscall0(SYS_LCHFLAGS);
}

pub unsafe fn lchmod() {
    core::unimplemented!();
    // syscall0(SYS_LCHMOD);
}

pub unsafe fn lgetfh() {
    core::unimplemented!();
    // syscall0(SYS_LGETFH);
}

pub unsafe fn lio_listio() {
    core::unimplemented!();
    // syscall0(SYS_LIO_LISTIO);
}

pub unsafe fn lpathconf() {
    core::unimplemented!();
    // syscall0(SYS_LPATHCONF);
}

pub unsafe fn lutimes() {
    core::unimplemented!();
    // syscall0(SYS_LUTIMES);
}

pub unsafe fn mac_syscall() {
    core::unimplemented!();
    // syscall0(SYS_MAC_SYSCALL);
}

pub unsafe fn mincore() {
    core::unimplemented!();
    // syscall0(SYS_MINCORE);
}

pub unsafe fn minherit() {
    core::unimplemented!();
    // syscall0(SYS_MINHERIT);
}

pub unsafe fn mkfifo() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFO);
}

pub unsafe fn mkfifoat() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFOAT);
}

pub unsafe fn modfind() {
    core::unimplemented!();
    // syscall0(SYS_MODFIND);
}

pub unsafe fn modfnext() {
    core::unimplemented!();
    // syscall0(SYS_MODFNEXT);
}

pub unsafe fn modnext() {
    core::unimplemented!();
    // syscall0(SYS_MODNEXT);
}

pub unsafe fn modstat() {
    core::unimplemented!();
    // syscall0(SYS_MODSTAT);
}

pub unsafe fn nmount() {
    core::unimplemented!();
    // syscall0(SYS_NMOUNT);
}

pub unsafe fn nosys() {
    core::unimplemented!();
    // syscall0(SYS_NOSYS);
}

pub unsafe fn ntp_adjtime() {
    core::unimplemented!();
    // syscall0(SYS_NTP_ADJTIME);
}

pub unsafe fn ntp_gettime() {
    core::unimplemented!();
    // syscall0(SYS_NTP_GETTIME);
}

pub unsafe fn pathconf() {
    core::unimplemented!();
    // syscall0(SYS_PATHCONF);
}

pub unsafe fn pdfork() {
    core::unimplemented!();
    // syscall0(SYS_PDFORK);
}

pub unsafe fn pdgetpid() {
    core::unimplemented!();
    // syscall0(SYS_PDGETPID);
}

pub unsafe fn pdkill() {
    core::unimplemented!();
    // syscall0(SYS_PDKILL);
}

pub unsafe fn posix_fadvise() {
    core::unimplemented!();
    // syscall0(SYS_POSIX_FADVISE);
}

pub unsafe fn posix_fallocate() {
    core::unimplemented!();
    // syscall0(SYS_POSIX_FALLOCATE);
}

pub unsafe fn posix_openpt() {
    core::unimplemented!();
    // syscall0(SYS_POSIX_OPENPT);
}

pub unsafe fn pread() {
    core::unimplemented!();
    // syscall0(SYS_PREAD);
}

pub unsafe fn procctl() {
    core::unimplemented!();
    // syscall0(SYS_PROCCTL);
}

pub unsafe fn profil() {
    core::unimplemented!();
    // syscall0(SYS_PROFIL);
}

pub unsafe fn pselect() {
    core::unimplemented!();
    // syscall0(SYS_PSELECT);
}

pub unsafe fn ptrace() {
    core::unimplemented!();
    // syscall0(SYS_PTRACE);
}

pub unsafe fn pwrite() {
    core::unimplemented!();
    // syscall0(SYS_PWRITE);
}

pub unsafe fn rctl_add_rule() {
    core::unimplemented!();
    // syscall0(SYS_RCTL_ADD_RULE);
}

pub unsafe fn rctl_get_limits() {
    core::unimplemented!();
    // syscall0(SYS_RCTL_GET_LIMITS);
}

pub unsafe fn rctl_get_racct() {
    core::unimplemented!();
    // syscall0(SYS_RCTL_GET_RACCT);
}

pub unsafe fn rctl_get_rules() {
    core::unimplemented!();
    // syscall0(SYS_RCTL_GET_RULES);
}

pub unsafe fn rctl_remove_rule() {
    core::unimplemented!();
    // syscall0(SYS_RCTL_REMOVE_RULE);
}

pub unsafe fn revoke() {
    core::unimplemented!();
    // syscall0(SYS_REVOKE);
}

pub unsafe fn rfork() {
    core::unimplemented!();
    // syscall0(SYS_RFORK);
}

pub unsafe fn rtprio() {
    core::unimplemented!();
    // syscall0(SYS_RTPRIO);
}

pub unsafe fn rtprio_thread() {
    core::unimplemented!();
    // syscall0(SYS_RTPRIO_THREAD);
}

pub unsafe fn sbrk() {
    core::unimplemented!();
    // syscall0(SYS_SBRK);
}

pub unsafe fn setaudit() {
    core::unimplemented!();
    // syscall0(SYS_SETAUDIT);
}

pub unsafe fn setaudit_addr() {
    core::unimplemented!();
    // syscall0(SYS_SETAUDIT_ADDR);
}

pub unsafe fn setauid() {
    core::unimplemented!();
    // syscall0(SYS_SETAUID);
}

pub unsafe fn setcontext() {
    core::unimplemented!();
    // syscall0(SYS_SETCONTEXT);
}

/// Set effective group ID.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setgid(0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn setegid(egid: gid_t) -> Result<(), Errno> {
    let egid = egid as usize;
    syscall1(SYS_SETEGID, egid).map(drop)
}

/// Set effective user ID.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::setuid(0) };
/// assert_eq!(ret, Err(nc::EPERM));
/// ```
pub unsafe fn seteuid(euid: uid_t) -> Result<(), Errno> {
    let euid = euid as usize;
    syscall1(SYS_SETEUID, euid).map(drop)
}

pub unsafe fn setfib() {
    core::unimplemented!();
    // syscall0(SYS_SETFIB);
}

pub unsafe fn setlogin() {
    core::unimplemented!();
    // syscall0(SYS_SETLOGIN);
}

pub unsafe fn setloginclass() {
    core::unimplemented!();
    // syscall0(SYS_SETLOGINCLASS);
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

pub unsafe fn shm_open() {
    core::unimplemented!();
    // syscall0(SYS_SHM_OPEN);
}

pub unsafe fn shm_unlink() {
    core::unimplemented!();
    // syscall0(SYS_SHM_UNLINK);
}

pub unsafe fn sigqueue() {
    core::unimplemented!();
    // syscall0(SYS_SIGQUEUE);
}

pub unsafe fn sigtimedwait() {
    core::unimplemented!();
    // syscall0(SYS_SIGTIMEDWAIT);
}

pub unsafe fn sigwait() {
    core::unimplemented!();
    // syscall0(SYS_SIGWAIT);
}

pub unsafe fn sigwaitinfo() {
    core::unimplemented!();
    // syscall0(SYS_SIGWAITINFO);
}

pub unsafe fn socket() {
    core::unimplemented!();
    // syscall0(SYS_SOCKET);
}

pub unsafe fn sstk() {
    core::unimplemented!();
    // syscall0(SYS_SSTK);
}

pub unsafe fn sysarch() {
    core::unimplemented!();
    // syscall0(SYS_SYSARCH);
}

pub unsafe fn thr_create() {
    core::unimplemented!();
    // syscall0(SYS_THR_CREATE);
}

pub unsafe fn thr_exit() {
    core::unimplemented!();
    // syscall0(SYS_THR_EXIT);
}

pub unsafe fn thr_kill() {
    core::unimplemented!();
    // syscall0(SYS_THR_KILL);
}

pub unsafe fn thr_kill2() {
    core::unimplemented!();
    // syscall0(SYS_THR_KILL2);
}

pub unsafe fn thr_new() {
    core::unimplemented!();
    // syscall0(SYS_THR_NEW);
}

pub unsafe fn thr_self() {
    core::unimplemented!();
    // syscall0(SYS_THR_SELF);
}

pub unsafe fn thr_set_name() {
    core::unimplemented!();
    // syscall0(SYS_THR_SET_NAME);
}

pub unsafe fn thr_suspend() {
    core::unimplemented!();
    // syscall0(SYS_THR_SUSPEND);
}

pub unsafe fn thr_wake() {
    core::unimplemented!();
    // syscall0(SYS_THR_WAKE);
}

pub unsafe fn undelete() {
    core::unimplemented!();
    // syscall0(SYS_UNDELETE);
}

pub unsafe fn utrace() {
    core::unimplemented!();
    // syscall0(SYS_UTRACE);
}

pub unsafe fn uuidgen() {
    core::unimplemented!();
    // syscall0(SYS_UUIDGEN);
}

pub unsafe fn wait6() {
    core::unimplemented!();
    // syscall0(SYS_WAIT6);
}

pub unsafe fn r#yield() {
    core::unimplemented!();
    // syscall0(SYS_YIELD);
}

pub unsafe fn _umtx_op() {
    core::unimplemented!();
    // syscall0(SYS__UMTX_OP);
}

pub unsafe fn __acl_aclcheck_fd() {
    core::unimplemented!();
    // syscall0(SYS___ACL_ACLCHECK_FD);
}

pub unsafe fn __acl_aclcheck_file() {
    core::unimplemented!();
    // syscall0(SYS___ACL_ACLCHECK_FILE);
}

pub unsafe fn __acl_aclcheck_link() {
    core::unimplemented!();
    // syscall0(SYS___ACL_ACLCHECK_LINK);
}

pub unsafe fn __acl_delete_fd() {
    core::unimplemented!();
    // syscall0(SYS___ACL_DELETE_FD);
}

pub unsafe fn __acl_delete_file() {
    core::unimplemented!();
    // syscall0(SYS___ACL_DELETE_FILE);
}

pub unsafe fn __acl_delete_link() {
    core::unimplemented!();
    // syscall0(SYS___ACL_DELETE_LINK);
}

pub unsafe fn __acl_get_fd() {
    core::unimplemented!();
    // syscall0(SYS___ACL_GET_FD);
}

pub unsafe fn __acl_get_file() {
    core::unimplemented!();
    // syscall0(SYS___ACL_GET_FILE);
}

pub unsafe fn __acl_get_link() {
    core::unimplemented!();
    // syscall0(SYS___ACL_GET_LINK);
}

pub unsafe fn __acl_set_fd() {
    core::unimplemented!();
    // syscall0(SYS___ACL_SET_FD);
}

pub unsafe fn __acl_set_file() {
    core::unimplemented!();
    // syscall0(SYS___ACL_SET_FILE);
}

pub unsafe fn __acl_set_link() {
    core::unimplemented!();
    // syscall0(SYS___ACL_SET_LINK);
}

pub unsafe fn __cap_rights_get() {
    core::unimplemented!();
    // syscall0(SYS___CAP_RIGHTS_GET);
}

pub unsafe fn __mac_execve() {
    core::unimplemented!();
    // syscall0(SYS___MAC_EXECVE);
}

pub unsafe fn __mac_get_fd() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_FD);
}

pub unsafe fn __mac_get_file() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_FILE);
}

pub unsafe fn __mac_get_link() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_LINK);
}

pub unsafe fn __mac_get_pid() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_PID);
}

pub unsafe fn __mac_get_proc() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_PROC);
}

pub unsafe fn __mac_set_fd() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_FD);
}

pub unsafe fn __mac_set_file() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_FILE);
}

pub unsafe fn __mac_set_link() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_LINK);
}

pub unsafe fn __mac_set_proc() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_PROC);
}

pub unsafe fn __setugid() {
    core::unimplemented!();
    // syscall0(SYS___SETUGID);
}

pub unsafe fn __sysctl() {
    core::unimplemented!();
    // syscall0(SYS___SYSCTL);
}

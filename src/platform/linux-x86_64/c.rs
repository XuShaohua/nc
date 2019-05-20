
use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

fn c_str(s: &str) -> [u8; 128]{
    // TODO(Shaohua): Simplify ops
    let mut buf: [u8; 128] = [42; 128];
    for (i, b) in s.bytes().enumerate() {
        buf[i] = b;
    }
    // TODO(Shaohua): Assert length
    buf[s.len()] = 0;
    return buf;
}

#[inline(always)]
pub fn is_errno(ret: usize) -> bool {
    let reti = ret as isize;
    return reti < 0 && reti >= -256;
}


/// Accept a connection on a socket.
pub fn accept(sockfd: i32, addr: &mut sockaddr_in_t, addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let ret = syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn accept4() {
    // TODO(Shaohua): Not implemented
}

/// Check user's permission for a file.
pub fn access(path: &str, mode: i32) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_ACCESS, path, mode);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// set an alarm clock for delivery of a signal.
pub fn alarm(seconds: u32) -> u32 {
    unsafe {
        let seconds = seconds as usize;
        let ret = syscall1(SYS_ALARM, seconds);
        let ret = ret as u32;
        return ret;
    }
}

/// Bind a name to a socket.
pub fn bind(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *const sockaddr_in_t as usize;
        let addrlen = addrlen as usize;
        let ret = syscall3(SYS_BIND, sockfd, addr_ptr, addrlen);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change data segment size.
pub fn brk(addr: usize) -> Result<(), Errno> {
    unsafe {
        let ret = syscall1(SYS_BRK, addr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn clone() {
    // TODO(Shaohua): Not implemented
}

/// Close a file descriptor.
pub fn close(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let ret = syscall1(SYS_CLOSE, fd);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Initialize a connection on a socket.
pub fn connect(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        // TODO(Shaohua): Use sockaddr_t generic type.
        let addr_ptr = addr as *const sockaddr_in_t as usize;
        let addrlen = addrlen as usize;
        let ret = syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
pub fn dup(oldfd: i32) -> Result<isize, Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let ret = syscall1(SYS_DUP, oldfd);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as isize;
            return Ok(ret);
        }
    }
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
pub fn dup2(oldfd: i32, newfd: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        let ret = syscall2(SYS_DUP2, oldfd, newfd);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Save as `dup2()`, but can set the close-on-exec flag on `newfd`.
pub fn dup3(oldfd: i32, newfd: i32, flags: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_DUP3, oldfd, newfd, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Execute a new program.
/*
pub fn execve(filename: &str, argv: &[str], env: &[str]) -> Result<(), Errno> {
    unsafe {
        let filename = c_str(filename).as_ptr() as usize;
        let argv_ptr = argv as *const [str] as usize;
        let env_ptr = env as *const [str] as usize;
        let ret = syscall3(SYS_EXECVE, filename, argv_ptr, env_ptr);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}
*/
pub fn execve() -> Result<(), Errno> {
    // TODO(Shaohua): Not implemented
    Ok(())
}

pub fn epoll_create() {
    // TODO(Shaohua): Not implemented
}

pub fn epoll_create1() {
    // TODO(Shaohua): Not implemented
}

pub fn epoll_ctl() {
    // TODO(Shaohua): Not implemented
}

pub fn epoll_pwait() {
    // TODO(Shaohua): Not implemented
}

pub fn epoll_wait() {
    // TODO(Shaohua): Not implemented
}

pub fn eventfd() {
    // TODO(Shaohua): Not implemented
}

pub fn eventfd2() {
    // TODO(Shaohua): Not implemented
}

/// Terminate current process.
pub fn exit(status: u8) {
    unsafe {
        syscall1(SYS_EXIT, status as usize);
    }
}

pub fn fanotify_init() {
    // TODO(Shaohua): Not implemented.
}

pub fn fanotify_mask() {
    // TODO(Shaohua): Not implemented.
}

/// Create a child process.
pub fn fork() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_FORK);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as pid_t;
            return Ok(ret);
        }
    }
}

/// Get file status about a file descriptor.
pub fn fstat(fd: i32) -> Result<stat_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let mut statbuf = stat_t::default();
        let statbuf_ptr = &mut statbuf as *mut stat_t as usize;
        let ret = syscall2(SYS_FSTAT, fd, statbuf_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(statbuf);
        }
    }
}

pub fn fsync() {
    // TODO(Shaohua): Not implemented
}

/// Get the effective group ID of the calling process.
pub fn getegid() -> gid_t {
    unsafe {
        return syscall0(SYS_GETEGID) as gid_t;
    }
}

/// Get the effective user ID of the calling process.
pub fn geteuid() -> uid_t {
    unsafe {
        return syscall0(SYS_GETEUID) as uid_t;
    }
}

/// Get the real group ID of the calling process.
pub fn getgid() -> gid_t {
    unsafe {
        return syscall0(SYS_GETGID) as gid_t;
    }
}

/// Get list of supplementary group Ids.
pub fn getgroups() {
    // TODO(Shaohua): Not implemented
}

/// Get value of an interval timer.
pub fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let curr_val_ptr = curr_val as *mut itimerval_t as usize;
        let ret = syscall2(SYS_GETITIMER, which, curr_val_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get name of connected peer socket.
pub fn getpeername(sockfd: i32, addr: &mut sockaddr_in_t,
                   addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let ret = syscall3(SYS_GETPEERNAME, sockfd, addr_ptr, addrlen_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Returns the PGID(process group ID) of the process specified by `pid`.
pub fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    unsafe {
        let pid = pid as usize;
        let ret = syscall1(SYS_GETPGID, pid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as pid_t;
            return Ok(ret);
        }
    }
}

/// Get the process group ID of the calling process.
pub fn getpgrp() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPGRP) as pid_t;
    }
}

/// Get the process ID (PID) of the calling process.
pub fn getpid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPID) as pid_t;
    }
}

/// Get the process ID of the parent of the calling process.
pub fn getppid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPPID) as pid_t;
    }
}

pub fn getresgid() {
    // TODO(Shaohua): Not implemented
}

pub fn getresuid() {
    // TODO(Shaohua): Not implemented
}

/// Get current address to which the socket `sockfd` is bound.
pub fn getsockname(sockfd: i32, addr: &mut sockaddr_in_t, 
                   addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let ret = syscall3(SYS_GETSOCKNAME, sockfd, addr_ptr, addrlen_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get options on sockets
pub fn getsockopt(sockfd: i32, level: i32, optname: i32, optval: &mut usize,
                  optlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let level = level as usize;
        let optname = optname as usize;
        let optval_ptr = optval as *mut usize as usize;
        let optlen_ptr = optlen as *mut socklen_t as usize;
        let ret = syscall5(SYS_GETSOCKOPT, sockfd, level, optname, optval_ptr, optlen_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get the real user ID of the calling process.
pub fn getuid() -> uid_t {
    unsafe {
        return syscall0(SYS_GETUID) as uid_t;
    }
}

pub fn ioctl() {
    // TODO(Shaohua): Not implemented
}

/// Send signal to a process.
pub fn kill(pid: pid_t, signal: i32) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let signal = signal as usize;
        let ret = syscall2(SYS_KILL, pid, signal);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Listen for connections on a socket.
pub fn listen(sockfd: i32, backlog: i32) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let backlog = backlog as usize;
        let ret = syscall2(SYS_LISTEN, sockfd, backlog);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Reposition file offset.
pub fn lseek(fd: i32, offset: off_t, whence: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let whence = whence as usize;
        let ret = syscall3(SYS_LSEEK, fd, offset, whence);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get file status about a file, without following symbolic.
pub fn lstat(path: &str) -> Result<stat_t, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mut statbuf = stat_t::default();
        let statbuf_ptr = &mut statbuf as *mut stat_t as usize;
        let ret = syscall2(SYS_STAT, path, statbuf_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(statbuf);
        }
    }
}

/// Give advice about use of memory.
pub fn madvise(addr: usize, len: size_t, advice: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let advice = advice as usize;
        let ret = syscall3(SYS_MADVISE, addr, len, advice);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn mbind() {
    // TODO(Shaohua): Not implemented
}

pub fn mincore() {
    // TODO(Shaohua): Not implemented
}

/// Map files or devices into memory.
pub fn mmap(len: size_t, prot: i32, flags: i32, fd: i32, offset: off_t) -> Result<usize, Errno> {
    unsafe {
        let addr = 0 as usize;
        let len = len as usize;
        let prot = prot as usize;
        let flags = flags as usize;
        let fd = fd as usize;
        let offset = offset as usize;
        let ret = syscall6(SYS_MMAP, addr, len, prot, flags, fd, offset);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(ret);
        }
    }
}

/// Set protection on a region of memory.
pub fn mprotect(addr: usize, len: size_t, prot: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let prot = prot as usize;
        let ret = syscall3(SYS_MPROTECT, addr, len, prot);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn mremap() {
    // TODO(Shaohua): Not implememented
}

pub fn msgctl(msqid: i32, cmd: i32, buf: &mut msqid_ds) -> Result<i32, Errno> {
    unsafe {
        let msqid = msqid as usize;
        let cmd = cmd as usize;
        let buf_ptr = buf as *mut msqid_ds as usize;
        let ret = syscall3(SYS_MSGCTL, msqid, cmd, buf_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Get a System V message queue identifier.
pub fn msgget(key: key_t, msgflg: i32) -> Result<i32, Errno> {
    unsafe {
        let key = key as usize;
        let msgflg = msgflg as usize;
        let ret = syscall2(SYS_MSGGET, key, msgflg);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

pub fn msgrcv(msqid: i32, msgq: usize, msgsz: size_t, msgtyp: isize) -> Result<ssize_t, Errno> {
    unsafe {
        let msqid = msqid as usize;
        let msgsz = msgsz as usize;
        let msgtyp = msgtyp as usize;
        let ret = syscall4(SYS_MSGRCV, msqid, msgq, msgsz, msgtyp);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Append the message to a System V message queue.
pub fn msgsnd(msqid: i32, msgq: usize, msgsz: size_t, msgflg: i32) -> Result<(), Errno> {
    unsafe {
        let msqid = msqid as usize;
        let msgsz = msgsz as usize;
        let msgflg = msgflg as usize;
        let ret = syscall4(SYS_MSGSND, msqid, msgq, msgsz, msgflg);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Synchronize a file with memory map.
pub fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_MSYNC, addr, len, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Unmap files or devices from memory.
pub fn munmap(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let ret = syscall2(SYS_MUNMAP, addr, len);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// High resolution sleep.
pub fn nanosleep(req: &timespec_t, rem: &mut timespec_t) -> Result<(), Errno> {
    unsafe {
        let req_ptr = req as *const timespec_t as usize;
        let rem_ptr = rem as *mut timespec_t as usize;
        let ret = syscall2(SYS_NANOSLEEP, req_ptr, rem_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn inotify_add_watch() {
    // TODO(Shaohua): Not implemented
}

pub fn inotify_init() {
    // TODO(Shaohua): Not implemented
}

pub fn inotify_init1() {
    // TODO(Shaohua): Not implemented
}

pub fn inotify_rm_watch() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_getsetattr() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_notify() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_open() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_timedreceive() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_timedsend() {
    // TODO(Shaohua): Not implemented
}

pub fn mq_unlink() {
    // TODO(Shaohua): Not implemented
}

/// Open and possibly create a file.
pub fn open(path: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_OPEN, path, flags, mode);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

// Pause the calling process to sleep until a signal is delivered.
pub fn pause() -> Result<(), Errno> {
    unsafe {
        let ret = syscall0(SYS_PAUSE);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a pipe
pub fn pipe(pipefd: &mut [i32; 2]) -> Result<(), Errno> {
    unsafe {
        let pipefd_ptr = pipefd.as_mut_ptr() as usize;
        let ret = syscall1(SYS_PAUSE, pipefd_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn pipe2() {
    // TODO(Shaohua): Not implemented
}

/// Wait for some event on file descriptors.
pub fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<(), Errno> {
    unsafe {
        let fds_ptr = fds.as_mut_ptr() as usize;
        let nfds = fds.len() as usize;
        let timeout = timeout as usize;
        let ret = syscall3(SYS_POLL, fds_ptr, nfds, timeout);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Read from a file descriptor without changing file offset.
pub fn pread64(fd: i32, buf: &mut [u8], offset: off_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        let offset = offset as usize;
        let ret = syscall4(SYS_PREAD64, fd, buf_ptr, len, offset);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Write to a file descriptor without changing file offset.
pub fn pwrite(fd: i32, buf: &[u8], offset: off_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        let offset = offset as usize;
        let ret = syscall4(SYS_PWRITE64, fd, buf_ptr, len, offset);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

/// Read from a file descriptor.
pub fn read(fd: i32, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let len = buf.len() as usize;
        let ret = syscall3(SYS_READ, fd, buf_ptr, len);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Read from a file descriptor into multiple buffers.
pub fn readv(fd: i32, iov: &mut [iovec_t]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_mut_ptr() as usize;
        let len = iov.len() as usize;
        let ret = syscall3(SYS_READV, fd, iov_ptr, len);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Receive a message from a socket.
pub fn recvfrom(sockfd: i32, buf: &mut [u8], flags: i32, src_addr: &mut sockaddr_in_t,
                addrlen: &mut socklen_t) -> Result<ssize_t, Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buflen = buf.len();
        let flags = flags as usize;
        let src_addr_ptr = src_addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let ret = syscall6(SYS_RECVFROM, sockfd, buf_ptr, buflen, flags,
                           src_addr_ptr, addrlen_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn recvmmsg() {
    // TODO(Shaohua): Not implemented
}

/// Receive a msg from a socket.
pub fn recvmsg(sockfd: i32, msg: &mut msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let msg_ptr = msg as *mut msghdr_t as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_RECVMSG, sockfd, msg_ptr, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn rename(oldpath: &str, newpath: &str) -> Result<(), Errno> {
    unsafe {
        let oldpath = c_str(oldpath).as_ptr() as usize;
        let newpath = c_str(newpath).as_ptr() as usize;
        let ret = syscall2(SYS_RENAME, oldpath, newpath);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn rt_sigaction() -> Result<(), Errno> {
    // TODO(Shaohua): Not implemented
    Ok(())
}

pub fn rt_sigprocmask() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigreturn() {
    // TODO(Shaohua): Not implemented
}

/// Yield the processor.
pub fn sched_yield() -> Result<(), Errno> {
    unsafe {
        let ret = syscall0(SYS_SCHED_YIELD);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Waiting one or more file descriptors become ready.
pub fn select() {
    // TODO(Shaohua): Not implemented.
}

pub fn semctl() {
    // TODO(Shaohua): Not implemented.
}

/// Get a System V semphore set identifier.
pub fn semget(key: key_t, nsems: i32, semflg: i32) -> Result<i32, Errno> {
    unsafe {
        let key = key as usize;
        let nsems = nsems as usize;
        let semflg = semflg as usize;
        let ret = syscall3(SYS_SEMGET, key, nsems, semflg);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// System V semphore operations.
pub fn semop(semid: i32, sops: &mut [sembuf_t]) -> Result<(), Errno> {
    unsafe {
        let semid = semid as usize;
        let sops_ptr = sops.as_ptr() as usize;
        let nops = sops.len();
        let ret = syscall3(SYS_SEMOP, semid, sops_ptr, nops);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Transfer data between two file descriptors.
pub fn sendfile(out_fd: i32, in_fd: i32, offset: &mut off_t,
                count: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let out_fd = out_fd as usize;
        let in_fd = in_fd as usize;
        let offset_ptr = offset as *mut off_t as usize;
        let count = count as usize;
        let ret = syscall4(SYS_SENDFILE, out_fd, in_fd, offset_ptr, count);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Send a message on a socket. Allow sending ancillary data.
pub fn sendmsg(sockfd: i32, msg: &msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let msg_ptr = msg as *const msghdr_t as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_SENDMSG, sockfd, msg_ptr, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Send a message on a socket.
pub fn sendto(sockfd: i32, buf: &[u8], flags: i32, dest_addr: &sockaddr_in_t,
              addrlen: socklen_t) -> Result<ssize_t, Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let buflen = buf.len() as usize;
        let flags = flags as usize;
        let dest_addr_ptr = dest_addr as *const sockaddr_in_t as usize;
        let addrlen = addrlen as usize;
        let ret = syscall6(SYS_SENDTO, sockfd, buf_ptr, buflen, flags, dest_addr_ptr, addrlen);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Set the group ID of the calling process to `gid`.
pub fn setgid(gid: gid_t) -> Result<(), Errno> {
    unsafe {
        let gid = gid as usize;
        let ret = syscall1(SYS_SETGID, gid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set list of supplementary group Ids.
pub fn setgroups() -> Result<(), Errno> {
    // TODO(Shaohua): not implemented
    Ok(())
}

/// Set value of an interval timer.
pub fn setitimer(which: i32, new_val: &itimerval_t,
                 old_val: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let new_val_ptr = new_val as *const itimerval_t as usize;
        let old_val_ptr = old_val as *mut itimerval_t as usize;
        let ret = syscall3(SYS_SETITIMER, which, new_val_ptr, old_val_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
pub fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let pgid = pgid as usize;
        let ret = syscall2(SYS_SETPGID, pid, pgid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set real and effective group IDs of the calling process.
pub fn setregid(rgid: gid_t, egid: gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid = rgid as usize;
        let egid = egid as usize;
        let ret = syscall2(SYS_SETREGID, rgid, egid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}


/// Set real and effective user IDs of the calling process.
pub fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid = ruid as usize;
        let euid = euid as usize;
        let ret = syscall2(SYS_SETREUID, ruid, euid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set real, effective and saved group Ids of the calling process.
pub fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid = rgid as usize;
        let egid = egid as usize;
        let sgid = sgid as usize;
        let ret = syscall3(SYS_SETREUID, rgid, egid, sgid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set real, effective and saved user Ids of the calling process.
pub fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid = ruid as usize;
        let euid = euid as usize;
        let suid = suid as usize;
        let ret = syscall3(SYS_SETREUID, ruid, euid, suid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a new session if the calling process is not a process group leader.
pub fn setsid() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_SETSID);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as pid_t;
            return Ok(ret);
        }
    }
}

/// Set options on sockets.
pub fn setsockopt(sockfd: i32, level: i32, optname: i32, optval: usize,
                  optlen: socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let level = level as usize;
        let optname = optname as usize;
        let optlen = optlen as usize;
        let ret = syscall5(SYS_SETSOCKOPT, sockfd, level, optname, optval, optlen);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set the effective user ID of the calling process to `uid`.
pub fn setuid(uid: uid_t) -> Result<(), Errno> {
    unsafe {
        let uid = uid as usize;
        let ret = syscall1(SYS_SETUID, uid);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Attach the System V shared memory segment.
pub fn shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> Result<usize, Errno> {
    unsafe {
        let shmid = shmid as usize;
        let shmflg = shmflg as usize;
        let ret = syscall3(SYS_SHMAT, shmid, shmaddr, shmflg);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(ret);
        }
    }
}

/// Detach the System V shared memory segment.
pub fn shmdt(shmaddr: usize) -> Result<(), Errno> {
    unsafe {
        let ret = syscall1(SYS_SHMDT, shmaddr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// System V shared memory control.
pub fn shmctl(shmid: i32, cmd: i32, buf: &mut shmid_ds) -> Result<i32, Errno> {
    unsafe {
        let shmid = shmid as usize;
        let cmd = cmd as usize;
        let buf_ptr = buf as *mut shmid_ds as usize;
        let ret = syscall3(SYS_SHMCTL, shmid, cmd, buf_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Allocates a System V shared memory segment.
pub fn shmget(key: key_t, size: size_t, shmflg: i32) -> Result<(), Errno> {
    unsafe {
        let key = key as usize;
        let size = size as usize;
        let shmflg = shmflg as usize;
        let ret = syscall3(SYS_SHMGET, key, size, shmflg);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Shutdown part of a full-duplex connection.
pub fn shutdown(sockfd: i32, how: i32) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let how = how as usize;
        let ret = syscall2(SYS_SHUTDOWN, sockfd, how);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn signalfd() {
    // TODO(Shaohua): Not implemented
}

/// Create an endpoint for communication.
pub fn socket(domain: i32, sock_type: i32, protocol: i32) -> Result<i32, Errno> {
    unsafe {
        let domain = domain as usize;
        let sock_type = sock_type as usize;
        let protocol = protocol as usize;
        let ret = syscall3(SYS_SOCKET, domain, sock_type, protocol);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

pub fn socketpair() {
    // TODO(Shaohua): Not implemented
}

pub fn splice() {
    // TODO(Shaohua): Not implemented
}

/// Get file status about a file.
pub fn stat(path: &str) -> Result<stat_t, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mut statbuf = stat_t::default();
        let statbuf_ptr = &mut statbuf as *mut stat_t as usize;
        let ret = syscall2(SYS_STAT, path, statbuf_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(statbuf);
        }
    }
}

/// Commit filesystem caches to disk.
pub fn sync() {
    unsafe {
        syscall0(SYS_SYNC);
    }
}

/// Commit filesystem cache related to `fd` to disk.
pub fn syncfs(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let ret = syscall1(SYS_SYNCFS, fd);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Sync a file segment to disk
pub fn sync_file_range(fd: i32, offset: off_t, nbytes: off_t, flags: i32) -> Result<(), Errno>{
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let nbytes = nbytes as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_SYNC_FILE_RANGE, fd, offset, nbytes, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn tee() {
    // TODO(Shaohua): Not implemented
}

pub fn timerfd_create() {
    // TODO(Shaohua): Not implemented
}

pub fn timerfd_gettime() {
    // TODO(Shaohua): Not implemented
}

pub fn timerfd_settime() {
    // TODO(Shaohua): Not implemented
}

/// Create a child process and wait until it is terminated.
pub fn vfork() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_VFORK);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(ret as pid_t);
        }
    }
}

/// Wait for process to change state.
pub fn wait4(pid: pid_t, wstatus: &mut i32, options: i32,
             rusage: &mut rusage_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let wstatus_ptr = wstatus as *mut i32 as usize;
        let options = options as usize;
        let rusage_ptr = rusage as *mut rusage_t as usize;
        let ret = syscall4(SYS_WAIT4, pid, wstatus_ptr, options, rusage_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn waitid() {
    // TODO(Shaohua): Not implemented
}

/// Write to a file descriptor.
pub fn write(fd: i32, buf: &[u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        let ret = syscall3(SYS_WRITE, fd, buf_ptr, len);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Write to a file descriptor from multiple buffers.
pub fn writev(fd: i32, iov: &[iovec_t]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_ptr() as usize;
        let len = iov.len() as usize;
        let ret = syscall3(SYS_WRITE, fd, iov_ptr, len);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

/// Get name and information about current kernel.
pub fn uname(buf: &mut utsname_t) -> Result<(), Errno> {
    unsafe {
        let buf_ptr = buf as *mut utsname_t as usize;
        let ret = syscall1(SYS_UNAME, buf_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn vmsplice() {
    // TODO(Shaohua): Not implemented
}


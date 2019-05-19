
use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall6};

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

/// Check user's permission for a file.
pub fn access(path: &str, mode: i32) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_ACCESS, path, mode);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Change data segment size.
pub fn brk(addr: usize) -> Result<(), Errno> {
    unsafe {
        let ret = syscall1(SYS_BRK, addr);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

pub fn execve() {
    // TODO(Shaohua): Not implemented
}

/// Terminate current process.
pub fn exit(status: u8) {
    unsafe {
        syscall1(SYS_EXIT, status as usize);
    }
}

/// Create a child process.
pub fn fork() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_FORK);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as pid_t);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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

pub fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    unsafe {
        let pid = pid as usize;
        let ret = syscall1(SYS_GETPGID, pid);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

pub fn mremap() {
    // TODO(Shaohua): Not implememented
}

/// Synchronize a file with memory map.
pub fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_MSYNC, addr, len, flags);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Open and possibly create a file.
pub fn open(path: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_OPEN, path, flags, mode);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Wait for some event on file descriptors.
pub fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<(), Errno> {
    unsafe {
        let fds_ptr = fds.as_mut_ptr() as usize;
        let nfds = fds.len() as usize;
        let timeout = timeout as usize;
        let ret = syscall3(SYS_POLL, fds_ptr, nfds, timeout);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Read from a file descriptor without changing file offset.
pub fn pread64(fd: i32, buf: &mut [u8], len: size_t, offset: off_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = len as usize;
        let offset = offset as usize;
        let ret = syscall4(SYS_PREAD64, fd, buf_ptr, len, offset);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Write to a file descriptor without changing file offset.
pub fn pwrite(fd: i32, buf: &[u8], len: size_t, offset: off_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = len as usize;
        let offset = offset as usize;
        let ret = syscall4(SYS_PWRITE64, fd, buf_ptr, len, offset);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

/// Read from a file descriptor.
pub fn read(fd: i32, buf: &mut [u8], len: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let len = len as usize;
        let ret = syscall3(SYS_READ, fd, buf_ptr, len);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Read from a file descriptor into multiple buffers.
pub fn readv(fd: i32, iov: &mut [iovec_t], len: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_mut_ptr() as usize;
        let len = len as usize;
        let ret = syscall3(SYS_READV, fd, iov_ptr, len);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Waiting one or more file descriptors become ready.
pub fn select() {
    // TODO(Shaohua): Not implemented.
}

/// Set the group ID of the calling process to `gid`.
pub fn setgid(gid: gid_t) -> Result<(), Errno> {
    unsafe {
        let gid = gid as usize;
        let ret = syscall1(SYS_SETGID, gid);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
pub fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let pgid = pgid as usize;
        let ret = syscall2(SYS_SETPGID, pid, pgid);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Create a new session if the calling process is not a process group leader.
pub fn setsid() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_SETSID);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            let ret = ret as pid_t;
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Get file status about a file.
pub fn stat(path: &str) -> Result<stat_t, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mut statbuf = stat_t::default();
        let statbuf_ptr = &mut statbuf as *mut stat_t as usize;
        let ret = syscall2(SYS_STAT, path, statbuf_ptr);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
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
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(());
        }
    }
}

/// Create a child process and wait until it is terminated.
pub fn vfork() -> Result<pid_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_VFORK);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as pid_t);
        }
    }
}

pub fn wait4() {
    // TODO(Shaohua): Not implemented.
}

pub fn waitid() {
    // TODO(Shaohua): Not implemented
}

/// Write to a file descriptor.
pub fn write(fd: i32, buf: &[u8], len: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = len as usize;
        let ret = syscall3(SYS_WRITE, fd, buf_ptr, len);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

/// Write to a file descriptor from multiple buffers.
pub fn writev(fd: i32, iov: &[iovec_t], len: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_ptr() as usize;
        let len = len as usize;
        let ret = syscall3(SYS_WRITE, fd, iov_ptr, len);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}


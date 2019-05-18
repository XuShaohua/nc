
use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4};

fn c_str(s: &str) -> [u8; 128]{
    let mut buf: [u8; 128] = [42; 128];
    for (i, b) in s.bytes().enumerate() {
        buf[i] = b;
    }
    // TODO(Shaohua): Assert length
    buf[s.len()] = 0;
    return buf;
}

/// Close a file descriptor.
pub fn close(fd: isize) -> Result<(), Errno> {
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

/// Creates a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
pub fn dup(oldfd: isize) -> Result<isize, Errno> {
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

/// Creates a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
pub fn dup2(oldfd: isize, newfd: isize) -> Result<(), Errno> {
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
pub fn dup3(oldfd: isize, newfd: isize, flags: isize) -> Result<(), Errno> {
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

pub fn open(path: &str, flags: i32, mode: mode_t) -> Result<isize, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_OPEN, path, flags, mode);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(reti);
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

/// Commit filesystem caches to disk.
pub fn sync() {
    unsafe {
        syscall0(SYS_SYNC);
    }
}

/// Commit filesystem cache related to `fd` to disk.
pub fn syncfs(fd: isize) -> Result<(), Errno> {
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

pub fn sync_file_range(fd: isize, offset: off_t, nbytes: off_t, flags: isize) -> Result<(), Errno>{
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

pub fn write(fd: isize, buf: &[u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_len = buf.len();
        let buf = buf.as_ptr() as usize;
        let ret = syscall3(SYS_WRITE, fd, buf, buf_len);
        let reti = ret as isize;
        if reti < 0 && reti >= -256 {
            return Err(-reti);
        } else {
            return Ok(ret as ssize_t);
        }
    }
}

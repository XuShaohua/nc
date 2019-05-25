
use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::consts;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

fn c_str(s: &str) -> [u8; 128] {
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

#[inline(always)]
pub fn is_errno2(ret: usize) -> Result<(), Errno>{
    let reti = ret as isize;
    if reti < 0 && reti >= -256 {
        let reti = (-reti) as Errno;
        return Err(reti);
    } else {
        return Ok(());
    }
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

/// Accept a connection on a socket.
pub fn accept4(sockfd: i32, addr: &mut sockaddr_in_t, addrlen: &mut socklen_t, flags: i32) -> Result<() ,Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_ACCEPT4, sockfd, addr_ptr, addrlen_ptr, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

/// Switch process accounting.
pub fn acct(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filepath_ptr = filename.as_ptr() as usize;
        let ret = syscall1(SYS_ACCT, filepath_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Tune kernel clock. Returns clock state on success.
pub fn adjtimex(buf: &mut timex_t) -> Result<i32, Errno> {
    unsafe {
        let buf_ptr = buf as *mut timex_t as usize;
        let ret = syscall1(SYS_ADJTIMEX, buf_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
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

pub fn arch_prctl() {
    // TODO(Shaohua): Not implemented.
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

/// Perform a command on an extended BPF map or program
pub fn bpf(cmd: i32, attr: &mut bpf_attr_t, size: u32) -> Result<i32, Errno> {
    unsafe {
        let cmd = cmd as usize;
        let attr_ptr = attr as *mut bpf_attr_t as usize;
        let size = size as usize;
        let ret = syscall3(SYS_BPF, cmd, attr_ptr, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
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

/// Get capabilities of thread.
pub fn capget(hdrp: &mut cap_user_header_t, data: &mut cap_user_data_t) -> Result<(), Errno> {
    unsafe {
        let hdrp_ptr = hdrp as *mut cap_user_header_t as usize;
        let data_ptr = data as *mut cap_user_data_t as usize;
        let ret = syscall2(SYS_CAPGET, hdrp_ptr, data_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set capabilities of thread.
pub fn capset(hdrp: &mut cap_user_header_t, data: &cap_user_data_t) -> Result<(), Errno> {
    unsafe {
        let hdrp_ptr = hdrp as *mut cap_user_header_t as usize;
        let data_ptr = data as *const cap_user_data_t as usize;
        let ret = syscall2(SYS_CAPSET, hdrp_ptr, data_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change working directory.
pub fn chdir(path: &str) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let ret = syscall1(SYS_CHDIR, path);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change permissions of a file.
pub fn chmod(filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_CHMOD, filename_ptr, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change ownership of a file.
pub fn chown(filename: &str, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        let ret = syscall3(SYS_CHOWN, filename_ptr, user, group);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change the root directory.
pub fn chroot(path: &str) -> Result<(), Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let ret = syscall1(SYS_CHROOT, path_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn clock_adjtime(which_clock: clockid_t, tx: &mut timex_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tx_ptr = tx as *mut timex_t as usize;
        let ret = syscall2(SYS_CLOCK_ADJTIME, which_clock, tx_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get resolution(precision) of the specific clock.
pub fn clock_getres(which_clock: clockid_t, tp: &mut timespec_t ) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *mut timespec_t as usize;
        let ret = syscall2(SYS_CLOCK_GETRES, which_clock, tp_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get time of specific clock.
pub fn clock_gettime(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *mut timespec_t as usize;
        let ret = syscall2(SYS_CLOCK_GETTIME, which_clock, tp_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// High resolution sleep with a specific clock.
pub fn clock_nanosleep(which_clock: clockid_t, flags: i32, rqtp: &timespec_t,
                       rmtp: &mut timespec_t) -> Result<(), Errno>{
    unsafe {
        let which_clock = which_clock as usize;
        let flags = flags as usize;
        let rqtp_ptr = rqtp as *const timespec_t as usize;
        let rmtp_ptr = rmtp as *mut timespec_t as usize;
        let ret = syscall4(SYS_CLOCK_NANOSLEEP, which_clock, flags, rqtp_ptr, rmtp_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set time of specific clock.
pub fn clock_settime(which_clock: clockid_t, tp: &timespec_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *const timespec_t as usize;
        let ret = syscall2(SYS_CLOCK_SETTIME, which_clock, tp_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
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

/// Copy a range of data from one file to another.
pub fn copy_file_range(fd_in: i32, off_in: &mut loff_t, fd_out: i32, off_out: &mut loff_t,
                       len: size_t, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd_in = fd_in as usize;
        let off_in_ptr = off_in as *mut loff_t as usize;
        let fd_out = fd_out as usize;
        let off_out_ptr = off_out as *mut loff_t as usize;
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall6(SYS_COPY_FILE_RANGE, fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Create a file.
/// equals to call `open()` with flags `O_CREAT|O_WRONLY|O_TRUNC`.
pub fn creat(path: &str, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_CREAT, path, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
pub fn dup(oldfd: i32) -> Result<isize, Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let ret = syscall1(SYS_DUP, oldfd);
        is_errno2(ret)?;
        let ret = ret as isize;
        return Ok(ret);
    }
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
pub fn dup2(oldfd: i32, newfd: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        let ret = syscall2(SYS_DUP2, oldfd, newfd);
        is_errno2(ret)
    }
}

/// Save as `dup2()`, but can set the close-on-exec flag on `newfd`.
pub fn dup3(oldfd: i32, newfd: i32, flags: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_DUP3, oldfd, newfd, flags);
        is_errno2(ret)
    }
}

/// Execute a new program.
pub fn execve(filename: &str, argv: &[&str], env: &[&str]) -> Result<(), Errno> {
    unsafe {
        let filename = c_str(filename).as_ptr() as usize;
        let argv_ptr = argv.as_ptr() as usize;
        let env_ptr = env.as_ptr() as usize;
        let ret = syscall3(SYS_EXECVE, filename, argv_ptr, env_ptr);
        is_errno2(ret)
    }
}

pub fn execveat() {
    // TODO(Shaohua): Not implemented
}

/// Open an epoll file descriptor.
pub fn epoll_create(size: i32) -> Result<i32, Errno> {
    unsafe {
        let size = size as usize;
        let ret = syscall1(SYS_EPOLL_CREATE, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Open an epoll file descriptor.
pub fn epoll_create1(flags: i32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        let ret = syscall1(SYS_EPOLL_CREATE1, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Control interface for an epoll file descriptor.
pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: &mut epoll_event_t) -> Result<(), Errno> {
    unsafe {
        let epfd = epfd as usize;
        let op = op as usize;
        let fd = fd as usize;
        let event_ptr = event as *mut epoll_event_t as usize;
        let ret = syscall4(SYS_EPOLL_CTL, epfd, op, fd, event_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Wait for an I/O event on an epoll file descriptor.
pub fn epoll_pwait(epfd: i32, op: i32, fd: i32, events: &mut epoll_event_t) -> Result<i32, Errno> {
    unsafe {
        let epfd = epfd as usize;
        let op = op as usize;
        let fd = fd as usize;
        let events_ptr = events as *mut epoll_event_t as usize;
        let ret = syscall4(SYS_EPOLL_PWAIT, epfd, op, fd, events_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Wait for an I/O event on an epoll file descriptor.
pub fn epoll_wait(epfd: i32, events: &mut epoll_event_t, maxevents: i32, timeout: i32) -> Result<i32, Errno> {
    unsafe {
        let epfd = epfd as usize;
        let events_ptr = events as *mut epoll_event_t as usize;
        let maxevents = maxevents as usize;
        let timeout = timeout as usize;
        let ret = syscall4(SYS_EPOLL_WAIT, epfd, events_ptr, maxevents, timeout);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Create a file descriptor for event notification.
pub fn eventfd(count: u32) -> Result<i32, Errno> {
    unsafe {
        let count = count as usize;
        let ret = syscall1(SYS_EVENTFD, count);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Create a file descriptor for event notification.
pub fn eventfd2(count: u32, flags: i32) -> Result<i32, Errno> {
    unsafe {
        let count = count as usize;
        let flags = flags as usize;
        let ret = syscall2(SYS_EVENTFD2, count, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Terminate current process.
pub fn exit(status: u8) {
    unsafe {
        syscall1(SYS_EXIT, status as usize);
    }
}

/// Exit all threads in a process's thread group.
pub fn exit_group(status: i32) {
    unsafe {
        let status = status as usize;
        let _ret = syscall1(SYS_EXIT_GROUP, status);
    }
}

/// Check user's permission for a file.
pub fn faccessat(dfd: i32, filename: &str, mode: i32) -> Result<(), Errno> {
    unsafe {
        let dfd = dfd as usize;
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_FACCESSAT, dfd, filename_ptr, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Manipulate file space.
pub fn fallocate(fd: i32, mode: i32, offset: loff_t, len: loff_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let mode = mode as usize;
        let offset = offset as usize;
        let len = len as usize;
        let ret = syscall4(SYS_FALLOCATE, fd, mode, offset, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create and initialize fanotify group.
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        let event_f_flags = event_f_flags as usize;
        let ret = syscall2(SYS_FANOTIFY_INIT, flags, event_f_flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Add, remove, or modify an fanotify mark on a filesystem object
pub fn fanotify_mask(fanotify_fd: i32, flags: u32, mask: u64, fd: i32, pathname: &str) -> Result<(), Errno> {
    unsafe {
        let fanotify_fd = fanotify_fd as usize;
        let flags = flags as usize;
        let mask = mask as usize;
        let fd = fd as usize;
        let pathname_ptr = pathname.as_ptr() as usize;
        let ret = syscall5(SYS_FANOTIFY_MARK, fanotify_fd, flags, mask, fd, pathname_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change working directory.
pub fn fchdir(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let ret = syscall1(SYS_FCHDIR, fd);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change permissions of a file.
pub fn fchmod(fd: i32, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_FCHMOD, fd, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Manipulate file descriptor.
pub fn fcntl() {
    // TODO(Shaohua): Not implemented.
}

/// Flush all modified in-core data (exclude metadata) refered by `fd` to disk.
pub fn fdatasync(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let ret = syscall1(SYS_FDATASYNC, fd);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change permissions of a file.
pub fn fchmodat(dirfd: i32, filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_FCHMODAT, dirfd, filename_ptr, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change ownership of a file.
pub fn fchown(fd: i32, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let user = user as usize;
        let group = group as usize;
        let ret = syscall3(SYS_FCHOWN, fd, user, group);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get extended attribute value.
pub fn fgetxattr(fd: i32,name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_FGETXATTR, fd, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn finit_module() {
    // TODO(Shaohua): Not implemented.
}

/// List extended attribute names.
pub fn flistxattr(fd: i32, list: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let list_ptr = list.as_mut_ptr() as usize;
        let len = list.len();
        let ret = syscall3(SYS_FLISTXATTR, fd, list_ptr, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Remove an extended attribute.
pub fn frmovexattr(fd: i32, name: &str) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        let ret = syscall2(SYS_FREMOVEXATTR, fd, name_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set extended attribute value.
pub fn fsetxattr(fd: i32,name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_FSETXATTR, fd, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Apply or remove an advisory lock on an open file.
pub fn flock(fd: i32, operation: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let operation = operation as usize;
        let ret = syscall2(SYS_FLOCK, fd, operation);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change ownership of a file.
pub fn fchownat(dirfd: i32, filename: &str, user: uid_t, group: gid_t, flag: i32) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        let flag = flag as usize;
        let ret = syscall5(SYS_FCHOWNAT, dirfd, filename_ptr, user, group, flag);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

/// Get filesystem statistics.
pub fn fstatfs(fd: i32, buf: &mut statfs_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf as *mut statfs_t as usize;
        let ret = syscall2(SYS_FSTATFS, fd, buf_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Flush all modified in-core data refered by `fd` to disk.
pub fn fsync(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let ret = syscall1(SYS_FSYNC, fd);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Truncate an opened file to a specified length.
pub fn ftruncate(fd: i32, length: off_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let length = length as usize;
        let ret = syscall2(SYS_FTRUNCATE, fd, length);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn futex() {
    // TODO(Shaohua): Not implemented.
}

pub fn futimesat() {
    // TODO(Shaohua): Not implemented.
}

pub fn get_robust_list() {
    // TODO(Shaohua): Not implemented.
}

pub fn get_thread_area() {
    // TODO(Shaohua): Not implemented.
}

/// Get extended attribute value.
pub fn getxattr(path: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_GETXATTR, path_ptr, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Determine CPU and NUMA node on which the calling thread is running.
pub fn getcpu(cpu: &mut u32, node: &mut u32, cache: &mut getcpu_cache_t) -> Result<(), Errno> {
    unsafe {
        let cpu_ptr = cpu as *mut u32 as usize;
        let node_ptr = node as *mut u32 as usize;
        let cache_ptr = cache as *mut getcpu_cache_t as usize;
        let ret = syscall3(SYS_GETCPU, cpu_ptr, node_ptr, cache_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get directory entries.
pub fn getdents() {
    // TODO(Shaohua): Not implemented.
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
pub fn getgroups(size: i32, group_list: &mut[gid_t]) -> Result<i32, Errno> {
    unsafe {
        let size = size as usize;
        let group_ptr = group_list.as_mut_ptr() as usize;
        let ret = syscall2(SYS_GETGROUPS, size, group_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
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

/// Get program scheduling priority.
pub fn getpriority(which: i32, who: i32) -> Result<i32, Errno> {
    unsafe {
        let which = which as usize;
        let who = who as usize;
        let ret = syscall2(SYS_GETPRIORITY, which, who);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let mut ret = ret as i32;
            if ret > consts::PRIO_MAX {
                ret = consts::PRIO_MAX - ret;
            }
            return Ok(ret);
        }
    }
}

/// Obtain a series of random bytes.
pub fn getrandom(buf: &mut [u8], flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        let flags = flags as usize;
        let ret = syscall3(SYS_GETRANDOM, buf_ptr, buf_len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Get real, effect and saved group ID.
pub fn getresgid(rgid: &mut gid_t, egid: &mut gid_t, sgid: &mut gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid_ptr = rgid as *mut gid_t as usize;
        let egid_ptr = egid as *mut gid_t as usize;
        let sgid_ptr = sgid as *mut gid_t as usize;
        let ret = syscall3(SYS_GETRESGID, rgid_ptr, egid_ptr, sgid_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get real, effect and saved user ID.
pub fn getresuid(ruid: &mut uid_t, euid: &mut uid_t, suid: &mut uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid_ptr = ruid as *mut uid_t as usize;
        let euid_ptr = euid as *mut uid_t as usize;
        let suid_ptr = suid as *mut uid_t as usize;
        let ret = syscall3(SYS_GETRESUID, ruid_ptr, euid_ptr, suid_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get resource limit.
pub fn getrlimit(resource: i32, rlim: &mut rlimit_t) -> Result<(), Errno> {
    unsafe {
        let resource = resource as usize;
        let rlim_ptr = rlim as *mut rlimit_t as usize;
        let ret = syscall2(SYS_GETRLIMIT, resource, rlim_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get resource usage.
pub fn getrusage(who: i32, usage: &mut rusage_t) -> Result<(), Errno> {
    unsafe {
        let who = who as usize;
        let usage_ptr = usage as *mut rusage_t as usize;
        let ret = syscall2(SYS_GETRUSAGE, who, usage_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get session Id.
pub fn getsid(pid: pid_t) -> pid_t {
    unsafe {
        let pid = pid as usize;
        let ret = syscall1(SYS_GETSID, pid);
        let ret = ret as pid_t;
        return ret;
    }
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

/// Get the caller's thread ID (TID).
pub fn gettid() -> pid_t {
    unsafe {
        let ret = syscall0(SYS_GETTID);
        let ret = ret as pid_t;
        return ret;
    }
}

/// Get time.
pub fn gettimeofday(timeval: &mut timeval_t, tz: &mut timezone_t) -> Result<(), Errno> {
    unsafe {
        let timeval_ptr = timeval as *mut timeval_t as usize;
        let tz_ptr = tz as *mut timezone_t as usize;
        let ret = syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr);
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

/// Add a watch to an initialized inotify instance.
pub fn inotify_add_watch(fd: i32, path: &str, mask: u32) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let path = c_str(path).as_ptr() as usize;
        let mask = mask as usize;
        let ret = syscall3(SYS_INOTIFY_ADD_WATCH, fd, path, mask);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Initialize an inotify instance.
pub fn inotify_init() -> Result<i32, Errno> {
    unsafe {
        let ret = syscall0(SYS_INOTIFY_INIT);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Initialize an inotify instance.
pub fn inotify_init1(flags: i32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        let ret = syscall1(SYS_INOTIFY_INIT1, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Remove an existing watch from an inotify instance.
pub fn inotify_rm_watch(fd: i32, wd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let wd = wd as usize;
        let ret = syscall2(SYS_INOTIFY_RM_WATCH, fd, wd);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn io_cancel() {
    // TODO(Shaohua): Not implemented
}

pub fn io_destroy() {
    // TODO(Shaohua): Not implemented
}

pub fn io_getevents() {
    // TODO(Shaohua): Not implemented
}

pub fn io_pgetevents() {
    // TODO(Shaohua): Not implemented
}

pub fn io_setup() {
    // TODO(Shaohua): Not implemented
}

pub fn io_submit() {
    // TODO(Shaohua): Not implemented
}

pub fn ioctl() {
    // TODO(Shaohua): Not implemented
}

/// Set port input/output permissions.
pub fn ioperm(from: usize, num: usize, turn_on: i32) -> Result<(), Errno> {
    unsafe {
        let turn_on = turn_on as usize;
        let ret = syscall3(SYS_IOPERM, from, num, turn_on);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn iopl() {
    // TODO(Shaohua): Not implemented
}

pub fn kcmp() {
    // TODO(Shaohua): Not implemented
}

pub fn kexec_file_load() {
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

/// Change ownership of a file.
pub fn lchown(filename: &str, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        let ret = syscall3(SYS_LCHOWN, filename_ptr, user, group);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get extended attribute value.
pub fn lgetxattr(path: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_LGETXATTR, path_ptr, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// List extended attribute names.
pub fn llistxattr(path: &str, list: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let list_ptr = list.as_mut_ptr() as usize;
        let len = list.len();
        let ret = syscall3(SYS_LLISTXATTR, path_ptr, list_ptr, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn lookup_dcookie() {
    // TODO(Shaohua): Not implemented.
}

/// Remove an extended attribute.
pub fn lrmovexattr(path: &str, name: &str) -> Result<(), Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let ret = syscall2(SYS_LREMOVEXATTR, path_ptr, name_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set extended attribute value.
pub fn lsetxattr(path: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_LSETXATTR, path_ptr, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Make a new name for a file.
pub fn link(oldpath: &str, newpath: &str) -> Result<(), Errno> {
    unsafe {
        let oldpath_ptr = oldpath.as_ptr() as usize;
        let newpath_ptr = newpath.as_ptr() as usize;
        let ret = syscall2(SYS_LINK, oldpath_ptr, newpath_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Make a new name for a file.
pub fn linkat(olddfd: i32, oldpath: &str, newdfd: i32, newpath: &str) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldpath_ptr = oldpath.as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newpath_ptr = newpath.as_ptr() as usize;
        let ret = syscall4(SYS_LINKAT, olddfd, oldpath_ptr, newdfd, newpath_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
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

/// List extended attribute names.
pub fn listxattr(path: &str, list: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let list_ptr = list.as_mut_ptr() as usize;
        let len = list.len();
        let ret = syscall3(SYS_LISTXATTR, path_ptr, list_ptr, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
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

pub fn membarrier() {
    // TODO(Shaohua): Not implemented
}

pub fn memfd_create() {
    // TODO(Shaohua): Not implemented
}

pub fn mincore() {
    // TODO(Shaohua): Not implemented
}

/// Create a directory.
pub fn mkdir(path: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall2(SYS_MKDIR, path, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a directory.
pub fn mkdirat(dirfd: i32, path: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let path = c_str(path).as_ptr() as usize;
        let mode = mode as usize;
        let ret = syscall3(SYS_MKDIRAT, dirfd, path, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a special or ordinary file.
pub fn mknod(path: &str, mode: mode_t, dev: dev_t) -> Result<(), Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let mode = mode as usize;
        let dev = dev as usize;
        let ret = syscall3(SYS_MKNOD, path_ptr, mode, dev);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a special or ordinary file.
pub fn mknodat(dirfd: i32, path: &str, mode: mode_t, dev: dev_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let path_ptr = path.as_ptr() as usize;
        let mode = mode as usize;
        let dev = dev as usize;
        let ret = syscall4(SYS_MKNODAT, dirfd, path_ptr, mode, dev);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Lock memory.
pub fn mlock(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let ret = syscall2(SYS_MLOCK, addr, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Lock memory.
pub fn mlock2(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall3(SYS_MLOCK2, addr, len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Lock memory.
pub fn mlockall(flags: i32) -> Result<(), Errno> {
    unsafe {
        let flags = flags as usize;
        let ret = syscall1(SYS_MLOCKALL, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

pub fn modify_ldt() {
    // TODO(Shaohua): Not implemented.
}

/// Mount filesystem.
pub fn mount(dev_name: &str, dir_name: &str, fs_type: &str, flags: usize, data: usize) -> Result<(), Errno> {
    unsafe {
        let dev_name_ptr = dev_name.as_ptr() as usize;
        let dir_name_ptr = dir_name.as_ptr() as usize;
        let fs_type_ptr = fs_type.as_ptr() as usize;
        let ret = syscall5(SYS_MOUNT, dev_name_ptr, dir_name_ptr, fs_type_ptr, flags, data);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn move_pages() {
    // TODO(Shaohua): Not implemented.
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

pub fn mremap() {
    // TODO(Shaohua): Not implemented
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

/// Unlock memory.
pub fn munlock(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let ret = syscall2(SYS_MUNLOCK, addr, len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Unlock memory.
pub fn munlockall() -> Result<(), Errno> {
    unsafe {
        let ret = syscall0(SYS_MUNLOCKALL);
        if is_errno(ret) {
            let ret = ret as Errno;
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

pub fn name_to_handle_at() {
    // TODO(Shaohua): Not implemented.
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

pub fn newfstatat() {
    // TODO(Shaohua): Not implemented
}

pub fn nfsserverctl() {
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

pub fn open_by_handle_at() {
    // TODO(Shaohua): Not implemented.
}

/// Open and possibly create a file within a directory.
pub fn openat(dirfd: i32, path: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        let ret = syscall4(SYS_OPENAT, dirfd, path, flags, mode);
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

pub fn perf_event_open() {
    // TODO(Shaohua): Not implemented.
}

pub fn personality() {
    // TODO(Shaohua): Not implemented.
}

/// Create a pipe
pub fn pipe2(pipefd: &mut [i32; 2]) -> Result<(), Errno> {
    unsafe {
        let pipefd_ptr = pipefd.as_mut_ptr() as usize;
        let ret = syscall1(SYS_PIPE, pipefd_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a pipe.
pub fn pipe(pipefd: &mut [i32; 2], flags: i32) -> Result<(), Errno> {
    unsafe {
        let pipefd_ptr = pipefd.as_mut_ptr() as usize;
        let flags = flags as usize;
        let ret = syscall2(SYS_PIPE, pipefd_ptr, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change the root filesystem.
pub fn pivotroot(new_root: &str, put_old: &str) -> Result<(), Errno> {
    unsafe {
        let new_root_ptr = new_root.as_ptr() as usize;
        let put_old_ptr = put_old.as_ptr() as usize;
        let ret = syscall2(SYS_PIVOT_ROOT, new_root_ptr, put_old_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Create a new protection key.
pub fn pkey_alloc(flags: usize, init_val: usize) -> Result<i32, Errno> {
    unsafe {
        let ret = syscall2(SYS_PKEY_ALLOC, flags, init_val);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Free a protection key.
pub fn pkey_free(pkey: i32) -> Result<(), Errno> {
    unsafe {
        let pkey = pkey as usize;
        let ret = syscall1(SYS_PKEY_FREE, pkey);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set protection on a region of memory.
pub fn pkey_mprotect(start: usize, len: size_t, prot: usize, pkey: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let pkey = pkey as usize;
        let ret = syscall4(SYS_PKEY_MPROTECT, start, len, prot, pkey);
        if is_errno(ret) {
            return Err(ret);
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
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn ppoll() {
    // TODO(Shaohua): Not implemented
}

/// Operations on a process.
pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> Result<i32, Errno> {
    unsafe {
        let option = option as usize;
        let arg2 = arg2 as usize;
        let arg3 = arg3 as usize;
        let arg4 = arg4 as usize;
        let arg5 = arg5 as usize;
        let ret = syscall5(SYS_PRCTL, option, arg2, arg3, arg4, arg5);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
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

/// Read from a file descriptor without changing file offset.
pub fn preadv(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let ret = syscall5(SYS_PREADV, fd, vec_ptr, vlen, pos_l, pos_h);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Read from a file descriptor without changing file offset.
pub fn preadv2(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize,
               flags: rwf_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let flags = flags as usize;
        let ret = syscall6(SYS_PREADV2, fd, vec_ptr, vlen, pos_l, pos_h, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn prlimit64() {
    // TODO(Shaohua): Not implemented
}

pub fn process_vm_readv() {
    // TODO(Shaohua): Not implemented
}

pub fn process_vm_writev() {
    // TODO(Shaohua): Not implemented
}

pub fn pselect6() {
    // TODO(Shaohua): Not implemented
}

pub fn ptrace() {
    // TODO(Shaohua): Not implemented
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

/// Write to a file descriptor without changing file offset.
pub fn pwritev(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let ret = syscall5(SYS_PWRITEV, fd, vec_ptr, vlen, pos_l, pos_h);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Write to a file descriptor without changing file offset.
pub fn pwritev2(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize,
                flags: rwf_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let flags = flags as usize;
        let ret = syscall6(SYS_PWRITEV2, fd, vec_ptr, vlen, pos_l, pos_h, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

pub fn query_module() {
    // TODO(Shaohua): Not implemented.
}

pub fn quotactl() {
    // TODO(Shaohua): Not implemented.
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

/// Initialize file head into page cache.
pub fn readahead(fd: i32, offset: off_t, count: size_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let count = count as usize;
        let ret = syscall3(SYS_READAHEAD, fd, offset, count);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Read value of a symbolic link.
pub fn readlink(path: &str, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        let ret = syscall3(SYS_READLINK, path_ptr, buf_ptr, buf_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Read value of a symbolic link.
pub fn readlinkat(dirfd: i32, path: &str, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let path_ptr = path.as_ptr() as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        let ret = syscall4(SYS_READLINKAT, dirfd, path_ptr, buf_ptr, buf_len);
        if is_errno(ret) {
            let ret = ret as Errno;
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

/// Reboot or enable/disable Ctrl-Alt-Del.
pub fn reboot(magic: i32, magci2: i32, cmd: u32, arg: usize) -> Result<(), Errno> {
    unsafe {
        let magic = magic as usize;
        let magic2 = magci2 as usize;
        let cmd = cmd as usize;
        let ret = syscall4(SYS_REBOOT, magic, magic2, cmd, arg);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
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

/// Remove an extended attribute.
pub fn rmovexattr(path: &str, name: &str) -> Result<(), Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let ret = syscall2(SYS_REMOVEXATTR, path_ptr, name_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change name or location of a file.
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

/// Change name or location of a file.
pub fn renameat(olddfd:i32, oldpath: &str, newdfd: i32, newpath: &str) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldpath = c_str(oldpath).as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newpath = c_str(newpath).as_ptr() as usize;
        let ret = syscall4(SYS_RENAMEAT, olddfd, oldpath, newdfd, newpath);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Change name or location of a file.
pub fn renameat2(olddfd:i32, oldpath: &str, newdfd: i32, newpath: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldpath = c_str(oldpath).as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newpath = c_str(newpath).as_ptr() as usize;
        let flags = flags as usize;
        let ret = syscall5(SYS_RENAMEAT2, olddfd, oldpath, newdfd, newpath, flags);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Delete a directory.
pub fn rmdir(path: &str) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let ret = syscall1(SYS_RMDIR, path);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn rseq() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigaction() -> Result<(), Errno> {
    // TODO(Shaohua): Not implemented
    Ok(())
}

pub fn rt_sigpending() {
}

pub fn rt_sigprocmask() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigqueueinfo() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigreturn() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigsuspend() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_sigtimedwait() {
    // TODO(Shaohua): Not implemented
}

pub fn rt_tgsigqueueinfo() {
    // TODO(Shaohua): Not implemented
}


/// Get scheduling paramters.
pub fn sched_getparam(pid: pid_t, param: &mut sched_param_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let param_ptr = param as *mut sched_param_t as usize;
        let ret = syscall2(SYS_SCHED_GETPARAM, pid, param_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get static priority max value.
pub fn sched_get_priority_max(policy: i32) -> Result<i32, Errno> {
    unsafe {
        let policy = policy as usize;
        let ret = syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Get static priority min value.
pub fn sched_get_priority_min(policy: i32) -> Result<i32, Errno> {
    unsafe {
        let policy = policy as usize;
        let ret = syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Get a thread's CPU affinity mask.
pub fn sched_getaffinity(pid: pid_t, len: u32, user_mask: &mut usize) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let len = len as usize;
        let user_mask_ptr = user_mask as *mut usize as usize;
        let ret = syscall3(SYS_SCHED_GETAFFINITY, pid, len, user_mask_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn sched_getattr() {
    // TODO(Shaohua): Not implemented.
}

/// Get scheduling parameter.
pub fn sched_getschedular(pid: pid_t) -> Result<i32, Errno> {
    unsafe {
        let pid = pid as usize;
        let ret = syscall1(SYS_SCHED_GETSCHEDULER, pid);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Get the SCHED_RR interval for the named process.
pub fn sched_rr_get_interval(pid: pid_t, interval: &mut timespec_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let interval_ptr = interval as *mut timespec_t as usize;
        let ret = syscall2(SYS_SCHED_RR_GET_INTERVAL, pid, interval_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set a thread's CPU affinity mask.
pub fn sched_setaffinity(pid: pid_t, len: u32, user_mask: &mut usize) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let len = len as usize;
        let user_mask_ptr = user_mask as *mut usize as usize;
        let ret = syscall3(SYS_SCHED_SETAFFINITY, pid, len, user_mask_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn sched_setattr() {
    // TODO(Shaohua): Not implemented.
}

/// Set scheduling paramters.
pub fn sched_setparam(pid: pid_t, param: &sched_param_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let param_ptr = param as *const sched_param_t as usize;
        let ret = syscall2(SYS_SCHED_SETPARAM, pid, param_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set scheduling parameter.
pub fn sched_setschedular(pid: pid_t, policy: i32, param: &sched_param_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let policy = policy as usize;
        let param_ptr = param as *const sched_param_t as usize;
        let ret = syscall3(SYS_SCHED_SETSCHEDULER, pid, policy, param_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

pub fn seccomp() {
    // TODO(Shaohua): Not implemented.
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

pub fn sendmmsg() {
    // TODO(Shaohua): Not implemented.
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

pub fn set_robust_list() {
    // TODO(Shaohua): Not implemented.
}

pub fn set_thread_area() {
    // TODO(Shaohua): Not implemented.
}

/// Set NIS domain name.
pub fn setdomainname(name: &str) -> Result<(), Errno> {
    unsafe {
        let name_ptr = c_str(name).as_ptr() as usize;
        let name_len = name.len() as usize;
        let ret = syscall2(SYS_SETDOMAINNAME, name_ptr, name_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set group identify used for filesystem checkes.
pub fn setfsgid(fsgid: gid_t) -> gid_t {
    unsafe {
        let fsgid = fsgid as usize;
        let ret = syscall1(SYS_SETFSGID, fsgid);
        let ret = ret as gid_t;
        return ret;
    }
}

/// Set user identify used for filesystem checkes.
pub fn setfsuid(fsuid: uid_t) -> uid_t {
    unsafe {
        let fsuid = fsuid as usize;
        let ret = syscall1(SYS_SETFSUID, fsuid);
        let ret = ret as uid_t;
        return ret;
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
pub fn setgroups(group_list: &[gid_t]) -> Result<(), Errno> {
    unsafe {
        let group_ptr = group_list.as_ptr() as usize;
        let group_len = group_list.len();
        let ret = syscall2(SYS_SETGROUPS, group_ptr, group_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set hostname
pub fn sethostname(name: &str) -> Result<(), Errno> {
    unsafe {
        let name_ptr = name.as_ptr() as usize;
        let name_len = name.len();
        let ret = syscall2(SYS_SETHOSTNAME, name_ptr, name_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

/// Reassociate thread with a namespace.
pub fn setns(fd: i32, nstype: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let nstype = nstype as usize;
        let ret = syscall2(SYS_SETNS, fd, nstype);
        if is_errno(ret) {
            let ret = ret as Errno;
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

pub fn setpriority(which: i32, who: i32, prio: i32) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let who = who as usize;
        let prio = prio as usize;
        let ret = syscall3(SYS_SETPRIORITY, which, who, prio);
        if is_errno(ret) {
            let ret = ret as Errno;
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

pub fn setrlimit() {
    // TODO(Shaohua): Not implemented.
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

/// Set system time and timezone.
pub fn settimeofday(timeval: &timeval_t, tz: &timezone_t) -> Result<(), Errno> {
    unsafe {
        let timeval_ptr = timeval as *const timeval_t as usize;
        let tz_ptr = tz as *const timezone_t as usize;
        let ret = syscall2(SYS_SETTIMEOFDAY, timeval_ptr, tz_ptr);
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

/// Set extended attribute value.
pub fn setxattr(path: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        let ret = syscall4(SYS_SETXATTR, path_ptr, name_ptr, value, size);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
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

pub fn sigaltstack() {
    // TODO(Shaohua): Not implemented.
}

/// Create a file descriptor to accept signals.
pub fn signalfd(fd: i32, mask: &[sigset_t]) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let mask_ptr = mask.as_ptr() as usize;
        let mask_len = mask.len() as usize;
        let ret = syscall3(SYS_SIGNALFD, fd, mask_ptr, mask_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Create a file descriptor to accept signals.
pub fn signalfd4(fd: i32, mask: &[sigset_t], flags: i32) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let mask_ptr = mask.as_ptr() as usize;
        let mask_len = mask.len() as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_SIGNALFD4, fd, mask_ptr, mask_len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
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

/// Splice data to/from pipe.
pub fn splice(fd_in: i32, off_in: &mut loff_t, fd_out: i32, off_out: &mut loff_t,
              len: size_t, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd_in = fd_in as usize;
        let off_in_ptr = off_in as *mut loff_t as usize;
        let fd_out = fd_out as usize;
        let off_out_ptr = off_out as *mut loff_t as usize;
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall6(SYS_SPLICE, fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
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
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(statbuf);
        }
    }
}

/// Get file status about a file (extended).
pub fn statx(dirfd: i32, path: &str, flags: i32, mask: u32, buf: &mut statx_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let mask = mask as usize;
        let buf_ptr = buf as *mut statx_t as usize;
        let ret = syscall5(SYS_STATX, dirfd, path, flags, mask, buf_ptr);
        if is_errno(ret) {
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get filesystem statistics.
pub fn statfs(path: &str, buf: &mut statfs_t) -> Result<(), Errno> {
    unsafe {
        let path_ptr = path.as_ptr() as usize;
        let buf_ptr = buf as *mut statfs_t as usize;
        let ret = syscall2(SYS_STATFS, path_ptr, buf_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Stop swapping to file/device.
pub fn swapoff(path: &str) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let ret = syscall1(SYS_SWAPOFF, path);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Start swapping to file/device.
pub fn swapon(path: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let flags = flags as usize;
        let ret = syscall2(SYS_SWAPON, path, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Make a new name for a file.
pub fn symlink(oldname: &str, newname: &str) -> Result<(), Errno> {
    unsafe {
        let oldname_ptr = oldname.as_ptr() as usize;
        let newname_ptr = newname.as_ptr() as usize;
        let ret = syscall2(SYS_SYMLINK, oldname_ptr, newname_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Make a new name for a file.
pub fn symlinkat(oldname: &str, newfd: i32, newname: &str) -> Result<(), Errno> {
    unsafe {
        let oldname_ptr = oldname.as_ptr() as usize;
        let newfd = newfd as usize;
        let newname_ptr = newname.as_ptr() as usize;
        let ret = syscall3(SYS_SYMLINKAT, oldname_ptr, newfd, newname_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
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

/// Read/write system parameters.
pub fn sysctl(args: &mut sysctl_args_t) -> Result<(), Errno> {
    unsafe {
        let args_ptr = args as *mut sysctl_args_t as usize;
        let ret = syscall1(SYS__SYSCTL, args_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get filesystem type information.
pub fn sysfs(option: i32, arg1: usize, arg2: usize) -> Result<i32, Errno> {
    unsafe {
        let option = option as usize;
        let arg1 = arg1 as usize;
        let arg2 = arg2 as usize;
        let ret = syscall3(SYS_SYSFS, option, arg1, arg2);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Return system information.
pub fn sysinfo(info: &mut sysinfo_t) -> Result<(), Errno> {
    unsafe {
        let info_ptr = info as *mut sysinfo_t as usize;
        let ret = syscall1(SYS_SYSINFO, info_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Read and/or clear kernel message ring buffer; set console_loglevel
pub fn syslog(action: i32, buf: &mut str) -> Result<i32, Errno> {
    unsafe {
        let action = action as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        let ret = syscall3(SYS_SYSLOG, action, buf_ptr, buf_len);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Duplicate pipe content.
pub fn tee(fd_in: i32, fd_out: i32, len: size_t, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd_in = fd_in as usize;
        let fd_out = fd_out as usize;
        let len = len as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_TEE, fd_in, fd_out, len, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}

/// Get time in seconds.
pub fn time() -> Result<time_t, Errno> {
    unsafe {
        let ret = syscall0(SYS_TIME);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as time_t;
            return Ok(ret);
        }
    }
}

/// Create a timer that notifies via a file descriptor.
pub fn timerfd_create(clockid: i32, flags: i32) -> Result<i32, Errno> {
    unsafe {
        let clockid = clockid as usize;
        let flags = flags as usize;
        let ret = syscall2(SYS_TIMERFD_CREATE, clockid, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as i32;
            return Ok(ret);
        }
    }
}

/// Get current timer via a file descriptor.
pub fn timerfd_gettime(ufd: i32, otmr: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let ufd = ufd as usize;
        let otmr_ptr = otmr as *mut itimerval_t as usize;
        let ret = syscall2(SYS_TIMERFD_GETTIME, ufd, otmr_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Set current timer via a file descriptor.
pub fn timerfd_settime(ufd: i32, flags: i32, utmr: &itimerval_t, otmr: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let ufd = ufd as usize;
        let flags = flags as usize;
        let utmr_ptr = utmr as *const itimerval_t as usize;
        let otmr_ptr = otmr as *mut itimerval_t as usize;
        let ret = syscall4(SYS_TIMERFD_SETTIME, ufd, flags, utmr_ptr, otmr_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Get process times.
pub fn times(buf: &mut tms_t) -> Result<clock_t, Errno> {
    unsafe {
        let buf_ptr = buf as *mut tms_t as usize;
        let ret = syscall1(SYS_TIMES, buf_ptr);
        if is_errno(ret) {
            let ret = ret as usize;
            return Err(ret);
        } else {
            let ret = ret as clock_t;
            return Ok(ret);
        }
    }
}

/// Truncate a file to a specified length.
pub fn truncate(path: &str, length: off_t) -> Result<(), Errno> {
    unsafe {
        let path = c_str(path).as_ptr() as usize;
        let length = length as usize;
        let ret = syscall2(SYS_TRUNCATE, path, length);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Send a signal to a thread.
pub fn tgkill(tgid: i32, tid: i32, sig: i32) -> Result<(), Errno> {
    unsafe {
        let tgid = tgid as usize;
        let tid = tid as usize;
        let sig = sig as usize;
        let ret = syscall3(SYS_TGKILL, tgid, tid, sig);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Send a signal to a thread (obsolete).
pub fn tkill(tid: i32, sig: i32) -> Result<(), Errno> {
    unsafe {
        let tid = tid as usize;
        let sig = sig as usize;
        let ret = syscall2(SYS_TKILL, tid, sig);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
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

/// Virtually hang up the current terminal.
pub fn vhangup() -> Result<(), Errno> {
    unsafe {
        let ret = syscall0(SYS_VHANGUP);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
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

/// Set file mode creation mask.
pub fn umask(mode: mode_t) -> Result<mode_t, Errno> {
    unsafe {
        let mode = mode as usize;
        let ret = syscall1(SYS_UMASK, mode);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as mode_t;
            return Ok(ret);
        }
    }
}

/// Umount filesystem.
pub fn umount2(name: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let name_ptr = name.as_ptr() as usize;
        let flags = flags as usize;
        let ret = syscall2(SYS_UMOUNT2, name_ptr, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
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

/// Delete a name and possibly the file it refers to.
pub fn unlink(pathname: &str) -> Result<(), Errno> {
    unsafe {
        let pathname_ptr = pathname.as_ptr() as usize;
        let ret = syscall1(SYS_UNLINK, pathname_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Delete a name and possibly the file it refers to.
pub fn unlinkat(dfd: i32, pathname: &str, flag: i32) -> Result<(), Errno> {
    unsafe {
        let dfd = dfd as usize;
        let pathname_ptr = pathname.as_ptr() as usize;
        let flag = flag as usize;
        let ret = syscall3(SYS_UNLINKAT, dfd, pathname_ptr, flag);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Disassociate parts of the process execution context
pub fn unshare(flags: i32) -> Result<(), Errno> {
    unsafe {
        let flags = flags as usize;
        let ret = syscall1(SYS_UNSHARE, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Load shared library.
pub fn uselib(library: &str) -> Result<(), Errno> {
    unsafe {
        let library_ptr = library.as_ptr() as usize;
        let ret = syscall1(SYS_USELIB, library_ptr);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

pub fn userfaultfd() {
    // TODO(Shaohua): Not implemented
}

pub fn ustat() {
    // TODO(Shaohua): Not implemented
}

pub fn utime() {
    // TODO(Shaohua): Not implemented
}

/// Change time timestamps with nanosecond precision.
pub fn utimensat(dirfd: i32, pathname: &str, times: &[timespec_t; 2], flags: i32) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let pathname_ptr = pathname.as_ptr() as usize;
        let times_ptr = times.as_ptr() as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_UTIMENSAT, dirfd, pathname_ptr, times_ptr, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            return Ok(());
        }
    }
}

/// Splice user page into a pipe.
pub fn vmsplice(fd: i32, iov: &iovec_t, nr_segs: usize, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov as *const iovec_t as usize;
        let flags = flags as usize;
        let ret = syscall4(SYS_VMSPLICE, fd, iov_ptr, nr_segs, flags);
        if is_errno(ret) {
            let ret = ret as Errno;
            return Err(ret);
        } else {
            let ret = ret as ssize_t;
            return Ok(ret);
        }
    }
}


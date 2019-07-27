
use crate::c_str::CString;

use super::errno::*;
use super::sysno::*;
use super::types::*;
use super::consts;
use super::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

/// Accept a connection on a socket.
pub fn accept(sockfd: i32, addr: &mut sockaddr_in_t, addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        return syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr)
            .map(|_ret| ());
    }
}

/// Accept a connection on a socket.
pub fn accept4(sockfd: i32, addr: &mut sockaddr_in_t, addrlen: &mut socklen_t, flags: i32) -> Result<() ,Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        let flags = flags as usize;
        return syscall4(SYS_ACCEPT4, sockfd, addr_ptr, addrlen_ptr, flags)
            .map(|_ret| ());
    }
}

/// Check user's permission for a file.
pub fn access(filename: &str, mode: i32) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall2(SYS_ACCESS, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Switch process accounting.
pub fn acct(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_ACCT, filename_ptr)
            .map(|_ret| ());
    }
}

/// Tune kernel clock. Returns clock state on success.
pub fn adjtimex(buf: &mut timex_t) -> Result<i32, Errno> {
    unsafe {
        let buf_ptr = buf as *mut timex_t as usize;
        return syscall1(SYS_ADJTIMEX, buf_ptr)
            .map(|ret| ret as i32);
    }
}

/// set an alarm clock for delivery of a signal.
pub fn alarm(seconds: u32) -> u32 {
    unsafe {
        let seconds = seconds as usize;
        return syscall1(SYS_ALARM, seconds).expect("alarm() failed") as u32;
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
        return syscall3(SYS_BIND, sockfd, addr_ptr, addrlen)
            .map(|_ret| ());
    }
}

/// Perform a command on an extended BPF map or program
pub fn bpf(cmd: i32, attr: &mut bpf_attr_t, size: u32) -> Result<i32, Errno> {
    unsafe {
        let cmd = cmd as usize;
        let attr_ptr = attr as *mut bpf_attr_t as usize;
        let size = size as usize;
        return syscall3(SYS_BPF, cmd, attr_ptr, size)
            .map(|ret| ret as i32);
    }
}

/// Change data segment size.
pub fn brk(addr: usize) -> Result<(), Errno> {
    unsafe {
        return syscall1(SYS_BRK, addr)
            .map(|_ret| ());
    }
}

/// Get capabilities of thread.
pub fn capget(hdrp: &mut cap_user_header_t, data: &mut cap_user_data_t) -> Result<(), Errno> {
    unsafe {
        let hdrp_ptr = hdrp as *mut cap_user_header_t as usize;
        let data_ptr = data as *mut cap_user_data_t as usize;
        return syscall2(SYS_CAPGET, hdrp_ptr, data_ptr)
            .map(|_ret| ());
    }
}

/// Set capabilities of thread.
pub fn capset(hdrp: &mut cap_user_header_t, data: &cap_user_data_t) -> Result<(), Errno> {
    unsafe {
        let hdrp_ptr = hdrp as *mut cap_user_header_t as usize;
        let data_ptr = data as *const cap_user_data_t as usize;
        return syscall2(SYS_CAPSET, hdrp_ptr, data_ptr)
            .map(|_ret| ());
    }
}

/// Change working directory.
pub fn chdir(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_CHDIR, filename_ptr)
            .map(|_ret| ());
    }
}

/// Change permissions of a file.
pub fn chmod(filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall2(SYS_CHMOD, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Change ownership of a file.
pub fn chown(filename: &str, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        return syscall3(SYS_CHOWN, filename_ptr, user, group)
            .map(|_ret| ());
    }
}

/// Change the root directory.
pub fn chroot(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_CHROOT, filename_ptr)
            .map(|_ret| ());
    }
}

pub fn clock_adjtime(which_clock: clockid_t, tx: &mut timex_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tx_ptr = tx as *mut timex_t as usize;
        return syscall2(SYS_CLOCK_ADJTIME, which_clock, tx_ptr)
            .map(|_ret| ());
    }
}

/// Get resolution(precision) of the specific clock.
pub fn clock_getres(which_clock: clockid_t, tp: &mut timespec_t ) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *mut timespec_t as usize;
        return syscall2(SYS_CLOCK_GETRES, which_clock, tp_ptr)
            .map(|_ret| ());
    }
}

/// Get time of specific clock.
pub fn clock_gettime(which_clock: clockid_t, tp: &mut timespec_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *mut timespec_t as usize;
        return syscall2(SYS_CLOCK_GETTIME, which_clock, tp_ptr)
            .map(|_ret| ());
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
        return syscall4(SYS_CLOCK_NANOSLEEP, which_clock, flags, rqtp_ptr, rmtp_ptr)
            .map(|_ret| ());
    }
}

/// Set time of specific clock.
pub fn clock_settime(which_clock: clockid_t, tp: &timespec_t) -> Result<(), Errno> {
    unsafe {
        let which_clock = which_clock as usize;
        let tp_ptr = tp as *const timespec_t as usize;
        return syscall2(SYS_CLOCK_SETTIME, which_clock, tp_ptr)
            .map(|_ret| ());
    }
}

pub fn clone() {
    // TODO(Shaohua): Not implemented
}

/// Close a file descriptor.
pub fn close(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        return syscall1(SYS_CLOSE, fd)
            .map(|_ret| ());
    }
}

/// Initialize a connection on a socket.
pub fn connect(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        // TODO(Shaohua): Use sockaddr_t generic type.
        let addr_ptr = addr as *const sockaddr_in_t as usize;
        let addrlen = addrlen as usize;
        return syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen)
            .map(|_ret| ());
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
        return syscall6(SYS_COPY_FILE_RANGE, fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags)
            .map(|ret| ret as ssize_t);
    }
}

/// Create a file.
/// equals to call `open()` with flags `O_CREAT|O_WRONLY|O_TRUNC`.
pub fn creat(filename: &str, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall2(SYS_CREAT, filename_ptr, mode)
            .map(|ret| ret as i32);
    }
}

/// Create a copy of the file descriptor `oldfd`, using the lowest available
/// file descriptor.
pub fn dup(oldfd: i32) -> Result<isize, Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        return syscall1(SYS_DUP, oldfd)
            .map(|ret| ret as isize);
    }
}

/// Create a copy of the file descriptor `oldfd`, using the speficified file
/// descriptor `newfd`.
pub fn dup2(oldfd: i32, newfd: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        return syscall2(SYS_DUP2, oldfd, newfd)
            .map(|_ret| ());
    }
}

/// Save as `dup2()`, but can set the close-on-exec flag on `newfd`.
pub fn dup3(oldfd: i32, newfd: i32, flags: i32) -> Result<(), Errno> {
    unsafe {
        let oldfd = oldfd as usize;
        let newfd = newfd as usize;
        let flags = flags as usize;
        return syscall3(SYS_DUP3, oldfd, newfd, flags)
            .map(|_ret| ());
    }
}

/// Execute a new program.
pub fn execve(filename: &str, argv: &[&str], env: &[&str]) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let argv_ptr = argv.as_ptr() as usize;
        let env_ptr = env.as_ptr() as usize;
        return syscall3(SYS_EXECVE, filename_ptr, argv_ptr, env_ptr)
            .map(|_ret| ());
    }
}

/// Execute a new program relative to a directory file descriptor.
pub fn execveat(fd: i32, filename: &str, argv: &[&str], env: &[&str], flags: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let argv_ptr = argv.as_ptr() as usize;
        let env_ptr = env.as_ptr() as usize;
        let flags = flags as usize;
        return syscall5(SYS_EXECVEAT, fd, filename_ptr, argv_ptr, env_ptr, flags)
            .map(|_ret| ());
    }
}

/// Open an epoll file descriptor.
pub fn epoll_create(size: i32) -> Result<i32, Errno> {
    unsafe {
        let size = size as usize;
        return syscall1(SYS_EPOLL_CREATE, size)
            .map(|ret| ret as i32);
    }
}

/// Open an epoll file descriptor.
pub fn epoll_create1(flags: i32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        return syscall1(SYS_EPOLL_CREATE1, flags)
            .map(|ret| ret as i32);
    }
}

/// Control interface for an epoll file descriptor.
pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: &mut epoll_event_t) -> Result<(), Errno> {
    unsafe {
        let epfd = epfd as usize;
        let op = op as usize;
        let fd = fd as usize;
        let event_ptr = event as *mut epoll_event_t as usize;
        return syscall4(SYS_EPOLL_CTL, epfd, op, fd, event_ptr)
            .map(|_ret| ());
    }
}

/// Wait for an I/O event on an epoll file descriptor.
pub fn epoll_pwait(epfd: i32, op: i32, fd: i32, events: &mut epoll_event_t) -> Result<i32, Errno> {
    unsafe {
        let epfd = epfd as usize;
        let op = op as usize;
        let fd = fd as usize;
        let events_ptr = events as *mut epoll_event_t as usize;
        return syscall4(SYS_EPOLL_PWAIT, epfd, op, fd, events_ptr)
            .map(|ret| ret as i32);
    }
}

/// Wait for an I/O event on an epoll file descriptor.
pub fn epoll_wait(epfd: i32, events: &mut epoll_event_t, maxevents: i32, timeout: i32) -> Result<i32, Errno> {
    unsafe {
        let epfd = epfd as usize;
        let events_ptr = events as *mut epoll_event_t as usize;
        let maxevents = maxevents as usize;
        let timeout = timeout as usize;
        return syscall4(SYS_EPOLL_WAIT, epfd, events_ptr, maxevents, timeout)
            .map(|ret| ret as i32);
    }
}

/// Create a file descriptor for event notification.
pub fn eventfd(count: u32) -> Result<i32, Errno> {
    unsafe {
        let count = count as usize;
        return syscall1(SYS_EVENTFD, count)
            .map(|ret| ret as i32);
    }
}

/// Create a file descriptor for event notification.
pub fn eventfd2(count: u32, flags: i32) -> Result<i32, Errno> {
    unsafe {
        let count = count as usize;
        let flags = flags as usize;
        return syscall2(SYS_EVENTFD2, count, flags)
            .map(|ret| ret as i32);
    }
}

/// Terminate current process.
pub fn exit(status: u8) {
    unsafe {
        let status = status as usize;
        let _ret = syscall1(SYS_EXIT, status);
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
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall3(SYS_FACCESSAT, dfd, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Predeclare an access pattern for file data.
pub fn fadvise64(fd: i32, offset: loff_t, len: loff_t, advice: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let len = len as usize;
        let advice = advice as usize;
        return syscall4(SYS_FADVISE64, fd, offset, len, advice)
            .map(|_ret| ());
    }
}

/// Manipulate file space.
pub fn fallocate(fd: i32, mode: i32, offset: loff_t, len: loff_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let mode = mode as usize;
        let offset = offset as usize;
        let len = len as usize;
        return syscall4(SYS_FALLOCATE, fd, mode, offset, len)
            .map(|_ret| ());
    }
}

/// Create and initialize fanotify group.
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        let event_f_flags = event_f_flags as usize;
        return syscall2(SYS_FANOTIFY_INIT, flags, event_f_flags)
            .map(|ret| ret as i32);
    }
}

/// Add, remove, or modify an fanotify mark on a filesystem object
pub fn fanotify_mask(fanotify_fd: i32, flags: u32, mask: u64, fd: i32,
                     filename: &str) -> Result<(), Errno> {
    unsafe {
        let fanotify_fd = fanotify_fd as usize;
        let flags = flags as usize;
        let mask = mask as usize;
        let fd = fd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall5(SYS_FANOTIFY_MARK, fanotify_fd, flags, mask, fd, filename_ptr)
            .map(|_ret| ());
    }
}

/// Change working directory.
pub fn fchdir(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        return syscall1(SYS_FCHDIR, fd)
            .map(|_ret| ());
    }
}

/// Change permissions of a file.
pub fn fchmod(fd: i32, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let mode = mode as usize;
        return syscall2(SYS_FCHMOD, fd, mode)
            .map(|_ret| ());
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
        return syscall1(SYS_FDATASYNC, fd)
            .map(|_ret| ());
    }
}

/// Change permissions of a file.
pub fn fchmodat(dirfd: i32, filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall3(SYS_FCHMODAT, dirfd, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Change ownership of a file.
pub fn fchown(fd: i32, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let user = user as usize;
        let group = group as usize;
        return syscall3(SYS_FCHOWN, fd, user, group)
            .map(|_ret| ());
    }
}

/// Get extended attribute value.
pub fn fgetxattr(fd: i32,name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_FGETXATTR, fd, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
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
        return syscall3(SYS_FLISTXATTR, fd, list_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Remove an extended attribute.
pub fn frmovexattr(fd: i32, name: &str) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        return syscall2(SYS_FREMOVEXATTR, fd, name_ptr)
            .map(|_ret| ());
    }
}

/// Set extended attribute value.
pub fn fsetxattr(fd: i32,name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_FSETXATTR, fd, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
    }
}

/// Apply or remove an advisory lock on an open file.
pub fn flock(fd: i32, operation: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let operation = operation as usize;
        return syscall2(SYS_FLOCK, fd, operation)
            .map(|_ret| ());
    }
}

/// Change ownership of a file.
pub fn fchownat(dirfd: i32, filename: &str, user: uid_t, group: gid_t, flag: i32) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        let flag = flag as usize;
        return syscall5(SYS_FCHOWNAT, dirfd, filename_ptr, user, group, flag)
            .map(|_ret| ());
    }
}

/// Create a child process.
pub fn fork() -> Result<pid_t, Errno> {
    unsafe {
        return syscall0(SYS_FORK)
            .map(|ret| ret as pid_t);
    }
}

/// Get file status about a file descriptor.
pub fn fstat(fd: i32, statbuf: &mut stat_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let statbuf_ptr = statbuf as *mut stat_t as usize;
        return syscall2(SYS_FSTAT, fd, statbuf_ptr)
            .map(|_ret| ());
    }
}

/// Get filesystem statistics.
pub fn fstatfs(fd: i32, buf: &mut statfs_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf as *mut statfs_t as usize;
        return syscall2(SYS_FSTATFS, fd, buf_ptr)
            .map(|_ret| ());
    }
}

/// Flush all modified in-core data refered by `fd` to disk.
pub fn fsync(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        return syscall1(SYS_FSYNC, fd)
            .map(|_ret| ());
    }
}

/// Truncate an opened file to a specified length.
pub fn ftruncate(fd: i32, length: off_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let length = length as usize;
        return syscall2(SYS_FTRUNCATE, fd, length)
            .map(|_ret| ());
    }
}

pub fn futex() {
    // TODO(Shaohua): Not implemented.
}

/// Change timestamp of a file relative to a directory file discriptor.
pub fn futimesat(dirfd: i32, filename: &str, times: &[timeval_t; 2]) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let times_ptr = times.as_ptr() as usize;
        return syscall3(SYS_FUTIMESAT, dirfd, filename_ptr, times_ptr)
            .map(|_ret| ());
    }
}

pub fn get_robust_list() {
    // TODO(Shaohua): Not implemented.
}

pub fn get_thread_area() {
    // TODO(Shaohua): Not implemented.
}

/// Get extended attribute value.
pub fn getxattr(filename: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_GETXATTR, filename_ptr, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
    }
}

/// Determine CPU and NUMA node on which the calling thread is running.
pub fn getcpu(cpu: &mut u32, node: &mut u32, cache: &mut getcpu_cache_t) -> Result<(), Errno> {
    unsafe {
        let cpu_ptr = cpu as *mut u32 as usize;
        let node_ptr = node as *mut u32 as usize;
        let cache_ptr = cache as *mut getcpu_cache_t as usize;
        return syscall3(SYS_GETCPU, cpu_ptr, node_ptr, cache_ptr)
            .map(|_ret| ());
    }
}

/// Get directory entries.
pub fn getdents() {
    // TODO(Shaohua): Not implemented.
}

pub fn getdents64() {
    // TODO(Shaohua): Not implemented.
}

/// Get the effective group ID of the calling process.
pub fn getegid() -> gid_t {
    unsafe {
        return syscall0(SYS_GETEGID).expect("getegid() failed") as gid_t;
    }
}

/// Get the effective user ID of the calling process.
pub fn geteuid() -> uid_t {
    unsafe {
        return syscall0(SYS_GETEUID).expect("geteuid() failed") as uid_t;
    }
}

/// Get the real group ID of the calling process.
pub fn getgid() -> gid_t {
    unsafe {
        return syscall0(SYS_GETGID).expect("getgid() failed") as gid_t;
    }
}

/// Get list of supplementary group Ids.
pub fn getgroups(size: i32, group_list: &mut[gid_t]) -> Result<i32, Errno> {
    unsafe {
        let size = size as usize;
        let group_ptr = group_list.as_mut_ptr() as usize;
        return syscall2(SYS_GETGROUPS, size, group_ptr)
            .map(|ret| ret as i32);
    }
}

/// Get value of an interval timer.
pub fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let curr_val_ptr = curr_val as *mut itimerval_t as usize;
        return syscall2(SYS_GETITIMER, which, curr_val_ptr)
            .map(|_ret| ());
    }
}

/// Get name of connected peer socket.
pub fn getpeername(sockfd: i32, addr: &mut sockaddr_in_t,
                   addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        return syscall3(SYS_GETPEERNAME, sockfd, addr_ptr, addrlen_ptr)
            .map(|_ret| ());
    }
}

/// Returns the PGID(process group ID) of the process specified by `pid`.
pub fn getpgid(pid: pid_t) -> Result<pid_t, Errno> {
    unsafe {
        let pid = pid as usize;
        return syscall1(SYS_GETPGID, pid)
            .map(|ret| ret as pid_t);
    }
}

/// Get the process group ID of the calling process.
pub fn getpgrp() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPGRP).expect("getpgrp() failed") as pid_t;
    }
}

/// Get the process ID (PID) of the calling process.
pub fn getpid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPID).expect("getpid() failed") as pid_t;
    }
}

/// Get the process ID of the parent of the calling process.
pub fn getppid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETPPID).expect("getppid() failed") as pid_t;
    }
}

/// Get program scheduling priority.
pub fn getpriority(which: i32, who: i32) -> Result<i32, Errno> {
    unsafe {
        let which = which as usize;
        let who = who as usize;
        return syscall2(SYS_GETPRIORITY, which, who)
            .map(|ret| {
                let ret = ret as i32;
                if ret > consts::PRIO_MAX {
                    return consts::PRIO_MAX - ret;
                }
                return ret;
            });
    }
}

/// Obtain a series of random bytes.
pub fn getrandom(buf: &mut [u8], flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        let flags = flags as usize;
        return syscall3(SYS_GETRANDOM, buf_ptr, buf_len, flags)
            .map(|ret| ret as ssize_t);
    }
}

/// Get real, effect and saved group ID.
pub fn getresgid(rgid: &mut gid_t, egid: &mut gid_t, sgid: &mut gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid_ptr = rgid as *mut gid_t as usize;
        let egid_ptr = egid as *mut gid_t as usize;
        let sgid_ptr = sgid as *mut gid_t as usize;
        return syscall3(SYS_GETRESGID, rgid_ptr, egid_ptr, sgid_ptr)
            .map(|_ret| ());
    }
}

/// Get real, effect and saved user ID.
pub fn getresuid(ruid: &mut uid_t, euid: &mut uid_t, suid: &mut uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid_ptr = ruid as *mut uid_t as usize;
        let euid_ptr = euid as *mut uid_t as usize;
        let suid_ptr = suid as *mut uid_t as usize;
        return syscall3(SYS_GETRESUID, ruid_ptr, euid_ptr, suid_ptr)
            .map(|_ret| ());
    }
}

/// Get resource limit.
pub fn getrlimit(resource: i32, rlim: &mut rlimit_t) -> Result<(), Errno> {
    unsafe {
        let resource = resource as usize;
        let rlim_ptr = rlim as *mut rlimit_t as usize;
        return syscall2(SYS_GETRLIMIT, resource, rlim_ptr)
            .map(|_ret| ());
    }
}

/// Get resource usage.
pub fn getrusage(who: i32, usage: &mut rusage_t) -> Result<(), Errno> {
    unsafe {
        let who = who as usize;
        let usage_ptr = usage as *mut rusage_t as usize;
        return syscall2(SYS_GETRUSAGE, who, usage_ptr)
            .map(|_ret| ());
    }
}

/// Get session Id.
pub fn getsid(pid: pid_t) -> pid_t {
    unsafe {
        let pid = pid as usize;
        return syscall1(SYS_GETSID, pid).expect("getsid() failed") as pid_t;
    }
}

/// Get current address to which the socket `sockfd` is bound.
pub fn getsockname(sockfd: i32, addr: &mut sockaddr_in_t, 
                   addrlen: &mut socklen_t) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let addr_ptr = addr as *mut sockaddr_in_t as usize;
        let addrlen_ptr = addrlen as *mut socklen_t as usize;
        return syscall3(SYS_GETSOCKNAME, sockfd, addr_ptr, addrlen_ptr)
            .map(|_ret| ());
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
        return syscall5(SYS_GETSOCKOPT, sockfd, level, optname, optval_ptr, optlen_ptr)
            .map(|_ret| ());
    }
}

/// Get the caller's thread ID (TID).
pub fn gettid() -> pid_t {
    unsafe {
        return syscall0(SYS_GETTID).expect("getpid() failed") as pid_t;
    }
}

/// Get time.
pub fn gettimeofday(timeval: &mut timeval_t, tz: &mut timezone_t) -> Result<(), Errno> {
    unsafe {
        let timeval_ptr = timeval as *mut timeval_t as usize;
        let tz_ptr = tz as *mut timezone_t as usize;
        return syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr)
            .map(|_ret| ());
    }
}

/// Get the real user ID of the calling process.
pub fn getuid() -> uid_t {
    unsafe {
        return syscall0(SYS_GETUID).expect("getuid() failed") as uid_t;
    }
}

/// Add a watch to an initialized inotify instance.
pub fn inotify_add_watch(fd: i32, filename: &str, mask: u32) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mask = mask as usize;
        return syscall3(SYS_INOTIFY_ADD_WATCH, fd, filename_ptr, mask)
            .map(|ret| ret as i32);
    }
}

/// Initialize an inotify instance.
pub fn inotify_init() -> Result<i32, Errno> {
    unsafe {
        return syscall0(SYS_INOTIFY_INIT)
            .map(|ret| ret as i32);
    }
}

/// Initialize an inotify instance.
pub fn inotify_init1(flags: i32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        return syscall1(SYS_INOTIFY_INIT1, flags)
            .map(|ret| ret as i32);
    }
}

/// Remove an existing watch from an inotify instance.
pub fn inotify_rm_watch(fd: i32, wd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let wd = wd as usize;
        return syscall2(SYS_INOTIFY_RM_WATCH, fd, wd)
            .map(|_ret| ());
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

pub fn ioctl(fd: i32, cmd: i32, arg: usize) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let cmd = cmd as usize;
        return syscall3(SYS_IOCTL, fd, cmd, arg)
            .map(|_ret| ());
    }
}

/// Set port input/output permissions.
pub fn ioperm(from: usize, num: usize, turn_on: i32) -> Result<(), Errno> {
    unsafe {
        let turn_on = turn_on as usize;
        return syscall3(SYS_IOPERM, from, num, turn_on)
            .map(|_ret| ());
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
        return syscall2(SYS_KILL, pid, signal)
            .map(|_ret| ());
    }
}

/// Change ownership of a file.
pub fn lchown(filename: &str, user: uid_t, group: gid_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let user = user as usize;
        let group = group as usize;
        return syscall3(SYS_LCHOWN, filename_ptr, user, group)
            .map(|_ret| ());
    }
}

/// Get extended attribute value.
pub fn lgetxattr(filename: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_LGETXATTR, filename_ptr, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
    }
}

/// List extended attribute names.
pub fn llistxattr(filename: &str, list: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let list_ptr = list.as_mut_ptr() as usize;
        let len = list.len();
        return syscall3(SYS_LLISTXATTR, filename_ptr, list_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

pub fn lookup_dcookie() {
    // TODO(Shaohua): Not implemented.
}

/// Remove an extended attribute.
pub fn lrmovexattr(filename: &str, name: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        return syscall2(SYS_LREMOVEXATTR, filename_ptr, name_ptr)
            .map(|_ret| ());
    }
}

/// Set extended attribute value.
pub fn lsetxattr(filename: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_LSETXATTR, filename_ptr, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
    }
}

/// Make a new name for a file.
pub fn link(oldfilename: &str, newfilename: &str) -> Result<(), Errno> {
    unsafe {
        let oldfilename = CString::new(oldfilename);
        let oldfilename_ptr = oldfilename.as_ptr() as usize;
        let newfilename = CString::new(newfilename);
        let newfilename_ptr = newfilename.as_ptr() as usize;
        return syscall2(SYS_LINK, oldfilename_ptr, newfilename_ptr)
            .map(|_ret| ());
    }
}

/// Make a new name for a file.
pub fn linkat(olddfd: i32, oldfilename: &str, newdfd: i32, newfilename: &str) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldfilename = CString::new(oldfilename);
        let oldfilename_ptr = oldfilename.as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newfilename = CString::new(newfilename);
        let newfilename_ptr = newfilename.as_ptr() as usize;
        return syscall4(SYS_LINKAT, olddfd, oldfilename_ptr, newdfd, newfilename_ptr)
            .map(|_ret| ());
    }
}

/// Listen for connections on a socket.
pub fn listen(sockfd: i32, backlog: i32) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let backlog = backlog as usize;
        return syscall2(SYS_LISTEN, sockfd, backlog)
            .map(|_ret| ());
    }
}

/// List extended attribute names.
pub fn listxattr(filename: &str, list: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let list_ptr = list.as_mut_ptr() as usize;
        let len = list.len();
        return syscall3(SYS_LISTXATTR, filename_ptr, list_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Reposition file offset.
pub fn lseek(fd: i32, offset: off_t, whence: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let whence = whence as usize;
        return syscall3(SYS_LSEEK, fd, offset, whence)
            .map(|_ret| ());
    }
}

/// Get file status about a file, without following symbolic.
pub fn lstat(filename: &str, statbuf: &mut stat_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let statbuf_ptr = statbuf as *mut stat_t as usize;
        return syscall2(SYS_STAT, filename_ptr, statbuf_ptr)
            .map(|_ret| ());
    }
}

/// Give advice about use of memory.
pub fn madvise(addr: usize, len: size_t, advice: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let advice = advice as usize;
        return syscall3(SYS_MADVISE, addr, len, advice)
            .map(|_ret| ());
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
pub fn mkdir(filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall2(SYS_MKDIR, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Create a directory.
pub fn mkdirat(dirfd: i32, filename: &str, mode: mode_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        return syscall3(SYS_MKDIRAT, dirfd, filename_ptr, mode)
            .map(|_ret| ());
    }
}

/// Create a special or ordinary file.
pub fn mknod(filename: &str, mode: mode_t, dev: dev_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        let dev = dev as usize;
        return syscall3(SYS_MKNOD, filename_ptr, mode, dev)
            .map(|_ret| ());
    }
}

/// Create a special or ordinary file.
pub fn mknodat(dirfd: i32, filename: &str, mode: mode_t, dev: dev_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let mode = mode as usize;
        let dev = dev as usize;
        return syscall4(SYS_MKNODAT, dirfd, filename_ptr, mode, dev)
            .map(|_ret| ());
    }
}

/// Lock memory.
pub fn mlock(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        return syscall2(SYS_MLOCK, addr, len)
            .map(|_ret| ());
    }
}

/// Lock memory.
pub fn mlock2(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let flags = flags as usize;
        return syscall3(SYS_MLOCK2, addr, len, flags)
            .map(|_ret| ());
    }
}

/// Lock memory.
pub fn mlockall(flags: i32) -> Result<(), Errno> {
    unsafe {
        let flags = flags as usize;
        return syscall1(SYS_MLOCKALL, flags)
            .map(|_ret| ());
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
        return syscall6(SYS_MMAP, addr, len, prot, flags, fd, offset);
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
        return syscall5(SYS_MOUNT, dev_name_ptr, dir_name_ptr, fs_type_ptr, flags, data)
            .map(|_ret| ());
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
        return syscall3(SYS_MPROTECT, addr, len, prot)
            .map(|_ret| ());
    }
}

/// Get/set message queue attributes
pub fn mq_getsetattr(mqdes: mqd_t, new_attr: &mut mq_attr_t, old_attr: &mut mq_attr_t) -> Result<mqd_t, Errno> {
    unsafe {
        let mqdes = mqdes as usize;
        let new_attr_ptr = new_attr as *mut mq_attr_t as usize;
        let old_attr_ptr = old_attr as *mut mq_attr_t as usize;
        return syscall3(SYS_MQ_GETSETATTR, mqdes, new_attr_ptr, old_attr_ptr)
            .map(|ret| ret as mqd_t);
    }
}

/// Register for notification when a message is available
pub fn mq_notify(mqdes: mqd_t, notification: &sigevent_t) -> Result<(), Errno> {
    unsafe {
        let mqdes = mqdes as usize;
        let notification_ptr = notification as *const sigevent_t as usize;
        return syscall2(SYS_MQ_NOTIFY, mqdes, notification_ptr)
            .map(|_ret| ());
    }
}

pub fn mq_open(name: &str, oflag: i32, mode: umode_t, attr: &mut mq_attr_t) -> Result<mqd_t, Errno> {
    unsafe {
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        let oflag = oflag as usize;
        let mode = mode as usize;
        let attr_ptr = attr as *mut mq_attr_t as usize;
        return syscall4(SYS_MQ_OPEN, name_ptr, oflag, mode, attr_ptr)
            .map(|ret| ret as mqd_t);
    }
}

/// Receive a message from a message queue
pub fn mq_timedreceive(mqdes: mqd_t, msg: &str, msg_prio: u32, abs_timeout: &timespec_t) -> Result<ssize_t, Errno> {
    unsafe {
        let mqdes = mqdes as usize;
        let msg = CString::new(msg);
        let msg_ptr = msg.as_ptr() as usize;
        let msg_len = msg.len();
        let msg_prio = msg_prio as usize;
        let abs_timeout_ptr = abs_timeout as *const timespec_t as usize;
        return syscall5(SYS_MQ_TIMEDRECEIVE, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout_ptr)
            .map(|ret| ret as ssize_t);
    }
}

/// Send message to a message queue
pub fn mq_timedsend(mqdes: mqd_t, msg: &str, msg_prio: u32, abs_timeout: &timespec_t) -> Result<(), Errno> {
    unsafe {
        let mqdes = mqdes as usize;
        let msg = CString::new(msg);
        let msg_ptr = msg.as_ptr() as usize;
        let msg_len = msg.len();
        let msg_prio = msg_prio as usize;
        let abs_timeout_ptr = abs_timeout as *const timespec_t as usize;
        return syscall5(SYS_MQ_TIMEDSEND, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout_ptr)
            .map(|_ret| ());
    }
}

/// Remove a message queue
pub fn mq_unlink(name: &str) -> Result<(), Errno> {
    unsafe {
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        return syscall1(SYS_MQ_UNLINK, name_ptr)
            .map(|_ret| ());
    }
}

/// Remap a virtual memory address
pub fn mremap(addr: usize, old_len: size_t, new_len: size_t, flags: usize, new_addr: usize) -> Result<usize, Errno> {
    unsafe {
        let old_len = old_len as usize;
        let new_len = new_len as usize;
        return syscall5(SYS_MREMAP, addr, old_len, new_len, flags, new_addr);
    }
}

pub fn msgctl(msqid: i32, cmd: i32, buf: &mut msqid_ds) -> Result<i32, Errno> {
    unsafe {
        let msqid = msqid as usize;
        let cmd = cmd as usize;
        let buf_ptr = buf as *mut msqid_ds as usize;
        return syscall3(SYS_MSGCTL, msqid, cmd, buf_ptr)
            .map(|ret| ret as i32);
    }
}

/// Get a System V message queue identifier.
pub fn msgget(key: key_t, msgflg: i32) -> Result<i32, Errno> {
    unsafe {
        let key = key as usize;
        let msgflg = msgflg as usize;
        return syscall2(SYS_MSGGET, key, msgflg)
            .map(|ret| ret as i32);
    }
}

pub fn msgrcv(msqid: i32, msgq: usize, msgsz: size_t, msgtyp: isize) -> Result<ssize_t, Errno> {
    unsafe {
        let msqid = msqid as usize;
        let msgsz = msgsz as usize;
        let msgtyp = msgtyp as usize;
        return syscall4(SYS_MSGRCV, msqid, msgq, msgsz, msgtyp)
            .map(|ret| ret as ssize_t);
    }
}

/// Append the message to a System V message queue.
pub fn msgsnd(msqid: i32, msgq: usize, msgsz: size_t, msgflg: i32) -> Result<(), Errno> {
    unsafe {
        let msqid = msqid as usize;
        let msgsz = msgsz as usize;
        let msgflg = msgflg as usize;
        return syscall4(SYS_MSGSND, msqid, msgq, msgsz, msgflg)
            .map(|_ret| ());
    }
}

/// Synchronize a file with memory map.
pub fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let flags = flags as usize;
        return syscall3(SYS_MSYNC, addr, len, flags)
            .map(|_ret| ());
    }
}

/// Unlock memory.
pub fn munlock(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        return syscall2(SYS_MUNLOCK, addr, len)
            .map(|_ret| ());
    }
}

/// Unlock memory.
pub fn munlockall() -> Result<(), Errno> {
    unsafe {
        return syscall0(SYS_MUNLOCKALL)
            .map(|_ret| ());
    }
}

/// Unmap files or devices from memory.
pub fn munmap(addr: usize, len: size_t) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        return syscall2(SYS_MUNMAP, addr, len)
            .map(|_ret| ());
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
        return syscall2(SYS_NANOSLEEP, req_ptr, rem_ptr)
            .map(|_ret| ());
    }
}

/// Get file status
pub fn newfstatat(dfd: i32, filename: &str, statbuf: &mut stat_t, flag: i32) -> Result<(), Errno> {
    unsafe {
        let dfd = dfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let statbuf_ptr = statbuf as *mut stat_t as usize;
        let flag = flag as usize;
        return syscall4(SYS_NEWFSTATAT, dfd, filename_ptr, statbuf_ptr, flag)
            .map(|_ret| ());
    }
}

/// Access kernel NFS daemon
//pub fn nfsservctl(cmd: i32, arg: &mut nfsctl_arg_t, resp: &mut fsctl_res_t) -> Result<(), Errno> {
//    unsafe {
//        let cmd = cmd as usize;
//        let arg_ptr = arg as *mut nfsctl_arg_t as usize;
//        let resp_ptr = resp as *mut fsctl_res_t as usize;
//        return syscall3(SYS_NFSSERVCTL, cmd, arg_ptr, resp_ptr)
//            .map(|_ret| ());
//    }
//}

/// Open and possibly create a file.
pub fn open(filename: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        return syscall3(SYS_OPEN, filename_ptr, flags, mode)
            .map(|ret| ret as i32);
    }
}

pub fn open_by_handle_at() {
    // TODO(Shaohua): Not implemented.
}

/// Open and possibly create a file within a directory.
pub fn openat(dirfd: i32, filename: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        return syscall4(SYS_OPENAT, dirfd, filename_ptr, flags, mode)
            .map(|ret| ret as i32);
    }
}

// Pause the calling process to sleep until a signal is delivered.
pub fn pause() -> Result<(), Errno> {
    unsafe {
        return syscall0(SYS_PAUSE)
            .map(|_ret| ());
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
        return syscall1(SYS_PIPE, pipefd_ptr)
            .map(|_ret| ());
    }
}

/// Create a pipe.
pub fn pipe(pipefd: &mut [i32; 2], flags: i32) -> Result<(), Errno> {
    unsafe {
        let pipefd_ptr = pipefd.as_mut_ptr() as usize;
        let flags = flags as usize;
        return syscall2(SYS_PIPE, pipefd_ptr, flags)
            .map(|_ret| ());
    }
}

/// Change the root filesystem.
pub fn pivotroot(new_root: &str, put_old: &str) -> Result<(), Errno> {
    unsafe {
        let new_root_ptr = new_root.as_ptr() as usize;
        let put_old_ptr = put_old.as_ptr() as usize;
        return syscall2(SYS_PIVOT_ROOT, new_root_ptr, put_old_ptr)
            .map(|_ret| ());
    }
}

/// Create a new protection key.
pub fn pkey_alloc(flags: usize, init_val: usize) -> Result<i32, Errno> {
    unsafe {
        return syscall2(SYS_PKEY_ALLOC, flags, init_val)
            .map(|ret| ret as i32);
    }
}

/// Free a protection key.
pub fn pkey_free(pkey: i32) -> Result<(), Errno> {
    unsafe {
        let pkey = pkey as usize;
        return syscall1(SYS_PKEY_FREE, pkey)
            .map(|_ret| ());
    }
}

/// Set protection on a region of memory.
pub fn pkey_mprotect(start: usize, len: size_t, prot: usize, pkey: i32) -> Result<(), Errno> {
    unsafe {
        let len = len as usize;
        let pkey = pkey as usize;
        return syscall4(SYS_PKEY_MPROTECT, start, len, prot, pkey)
            .map(|_ret| ());
    }
}

/// Wait for some event on file descriptors.
pub fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<(), Errno> {
    unsafe {
        let fds_ptr = fds.as_mut_ptr() as usize;
        let nfds = fds.len() as usize;
        let timeout = timeout as usize;
        return syscall3(SYS_POLL, fds_ptr, nfds, timeout)
            .map(|_ret| ());
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
        return syscall5(SYS_PRCTL, option, arg2, arg3, arg4, arg5)
            .map(|ret| ret as i32);
    }
}

/// Read from a file descriptor without changing file offset.
pub fn pread64(fd: i32, buf: &mut [u8], offset: off_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        let offset = offset as usize;
        return syscall4(SYS_PREAD64, fd, buf_ptr, len, offset)
            .map(|ret| ret as ssize_t);
    }
}

/// Read from a file descriptor without changing file offset.
pub fn preadv(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        return syscall5(SYS_PREADV, fd, vec_ptr, vlen, pos_l, pos_h)
            .map(|ret| ret as ssize_t);
    }
}

/// Read from a file descriptor without changing file offset.
pub fn preadv2(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize,
               flags: rwf_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let flags = flags as usize;
        return syscall6(SYS_PREADV2, fd, vec_ptr, vlen, pos_l, pos_h, flags)
            .map(|ret| ret as ssize_t);
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
        return syscall4(SYS_PWRITE64, fd, buf_ptr, len, offset)
            .map(|ret| ret as ssize_t);
    }
}

/// Write to a file descriptor without changing file offset.
pub fn pwritev(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        return syscall5(SYS_PWRITEV, fd, vec_ptr, vlen, pos_l, pos_h)
            .map(|ret| ret as ssize_t);
    }
}

/// Write to a file descriptor without changing file offset.
pub fn pwritev2(fd: i32, vec: &iovec_t, vlen: usize, pos_l: usize, pos_h: usize,
                flags: rwf_t) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let vec_ptr = vec as *const iovec_t as usize;
        let flags = flags as usize;
        return syscall6(SYS_PWRITEV2, fd, vec_ptr, vlen, pos_l, pos_h, flags)
            .map(|ret| ret as ssize_t);
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
        return syscall3(SYS_READ, fd, buf_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Initialize file head into page cache.
pub fn readahead(fd: i32, offset: off_t, count: size_t) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let count = count as usize;
        return syscall3(SYS_READAHEAD, fd, offset, count)
            .map(|_ret| ());
    }
}

/// Read value of a symbolic link.
pub fn readlink(filename: &str, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        return syscall3(SYS_READLINK, filename_ptr, buf_ptr, buf_len)
            .map(|ret| ret as ssize_t);
    }
}

/// Read value of a symbolic link.
pub fn readlinkat(dirfd: i32, filename: &str, buf: &mut [u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        return syscall4(SYS_READLINKAT, dirfd, filename_ptr, buf_ptr, buf_len)
            .map(|ret| ret as ssize_t);
    }
}

/// Read from a file descriptor into multiple buffers.
pub fn readv(fd: i32, iov: &mut [iovec_t]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_mut_ptr() as usize;
        let len = iov.len() as usize;
        return syscall3(SYS_READV, fd, iov_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Reboot or enable/disable Ctrl-Alt-Del.
pub fn reboot(magic: i32, magci2: i32, cmd: u32, arg: usize) -> Result<(), Errno> {
    unsafe {
        let magic = magic as usize;
        let magic2 = magci2 as usize;
        let cmd = cmd as usize;
        return syscall4(SYS_REBOOT, magic, magic2, cmd, arg)
            .map(|_ret| ());
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
        return syscall6(SYS_RECVFROM, sockfd, buf_ptr, buflen, flags,
                        src_addr_ptr, addrlen_ptr)
            .map(|ret| ret as ssize_t);
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
        return syscall3(SYS_RECVMSG, sockfd, msg_ptr, flags)
            .map(|ret| ret as ssize_t);
    }
}

pub fn remap_file_pages() {
    // TODO(Shaohua): Not implemented
}

/// Remove an extended attribute.
pub fn removexattr(filename: &str, name: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        return syscall2(SYS_REMOVEXATTR, filename_ptr, name_ptr)
            .map(|_ret| ());
    }
}

/// Change name or location of a file.
pub fn rename(oldfilename: &str, newfilename: &str) -> Result<(), Errno> {
    unsafe {
        let oldfilename = CString::new(oldfilename);
        let oldfilename_ptr = oldfilename.as_ptr() as usize;
        let newfilename = CString::new(newfilename);
        let newfilename_ptr = newfilename.as_ptr() as usize;
        return syscall2(SYS_RENAME, oldfilename_ptr, newfilename_ptr)
            .map(|_ret| ());
    }
}

/// Change name or location of a file.
pub fn renameat(olddfd:i32, oldfilename: &str, newdfd: i32, newfilename: &str) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldfilename = CString::new(oldfilename);
        let oldfilename_ptr = oldfilename.as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newfilename = CString::new(newfilename);
        let newfilename_ptr = newfilename.as_ptr() as usize;
        return syscall4(SYS_RENAMEAT, olddfd, oldfilename_ptr, newdfd, newfilename_ptr)
            .map(|_ret| ());
    }
}

/// Change name or location of a file.
pub fn renameat2(olddfd:i32, oldfilename: &str, newdfd: i32, newfilename: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let olddfd = olddfd as usize;
        let oldfilename = CString::new(oldfilename);
        let oldfilename_ptr = oldfilename.as_ptr() as usize;
        let newdfd = newdfd as usize;
        let newfilename = CString::new(newfilename);
        let newfilename_ptr = newfilename.as_ptr() as usize;
        let flags = flags as usize;
        return syscall5(SYS_RENAMEAT2, olddfd, oldfilename_ptr, newdfd, newfilename_ptr, flags)
            .map(|_ret| ());
    }
}

pub fn restart_syscall() {
    // TODO(Shaohua): Not implemented
}

/// Delete a directory.
pub fn rmdir(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_RMDIR, filename_ptr)
            .map(|_ret| ());
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
        return syscall2(SYS_SCHED_GETPARAM, pid, param_ptr)
            .map(|_ret| ());
    }
}

/// Get static priority max value.
pub fn sched_get_priority_max(policy: i32) -> Result<i32, Errno> {
    unsafe {
        let policy = policy as usize;
        return syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy)
            .map(|ret| ret as i32);
    }
}

/// Get static priority min value.
pub fn sched_get_priority_min(policy: i32) -> Result<i32, Errno> {
    unsafe {
        let policy = policy as usize;
        return syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy)
            .map(|ret| ret as i32);
    }
}

/// Get a thread's CPU affinity mask.
pub fn sched_getaffinity(pid: pid_t, len: u32, user_mask: &mut usize) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let len = len as usize;
        let user_mask_ptr = user_mask as *mut usize as usize;
        return syscall3(SYS_SCHED_GETAFFINITY, pid, len, user_mask_ptr)
            .map(|_ret| ());
    }
}

pub fn sched_getattr() {
    // TODO(Shaohua): Not implemented.
}

/// Get scheduling parameter.
pub fn sched_getschedular(pid: pid_t) -> Result<i32, Errno> {
    unsafe {
        let pid = pid as usize;
        return syscall1(SYS_SCHED_GETSCHEDULER, pid)
            .map(|ret| ret as i32);
    }
}

/// Get the SCHED_RR interval for the named process.
pub fn sched_rr_get_interval(pid: pid_t, interval: &mut timespec_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let interval_ptr = interval as *mut timespec_t as usize;
        return syscall2(SYS_SCHED_RR_GET_INTERVAL, pid, interval_ptr)
            .map(|_ret| ());
    }
}

/// Set a thread's CPU affinity mask.
pub fn sched_setaffinity(pid: pid_t, len: u32, user_mask: &mut usize) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let len = len as usize;
        let user_mask_ptr = user_mask as *mut usize as usize;
        return syscall3(SYS_SCHED_SETAFFINITY, pid, len, user_mask_ptr)
            .map(|_ret| ());
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
        return syscall2(SYS_SCHED_SETPARAM, pid, param_ptr)
            .map(|_ret| ());
    }
}

/// Set scheduling parameter.
pub fn sched_setschedular(pid: pid_t, policy: i32, param: &sched_param_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let policy = policy as usize;
        let param_ptr = param as *const sched_param_t as usize;
        return syscall3(SYS_SCHED_SETSCHEDULER, pid, policy, param_ptr)
            .map(|_ret| ());
    }
}

/// Yield the processor.
pub fn sched_yield() -> Result<(), Errno> {
    unsafe {
        return syscall0(SYS_SCHED_YIELD)
            .map(|_ret| ());
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
        return syscall3(SYS_SEMGET, key, nsems, semflg)
            .map(|ret| ret as i32);
    }
}

/// System V semphore operations.
pub fn semop(semid: i32, sops: &mut [sembuf_t]) -> Result<(), Errno> {
    unsafe {
        let semid = semid as usize;
        let sops_ptr = sops.as_ptr() as usize;
        let nops = sops.len();
        return syscall3(SYS_SEMOP, semid, sops_ptr, nops)
            .map(|_ret| ());
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
        return syscall4(SYS_SENDFILE, out_fd, in_fd, offset_ptr, count)
            .map(|ret| ret as ssize_t);
    }
}

/// Send a message on a socket. Allow sending ancillary data.
pub fn sendmsg(sockfd: i32, msg: &msghdr_t, flags: i32) -> Result<ssize_t, Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let msg_ptr = msg as *const msghdr_t as usize;
        let flags = flags as usize;
        return syscall3(SYS_SENDMSG, sockfd, msg_ptr, flags)
            .map(|ret| ret as ssize_t);
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
        return syscall6(SYS_SENDTO, sockfd, buf_ptr, buflen, flags, dest_addr_ptr, addrlen)
            .map(|ret| ret as ssize_t);
    }
}

pub fn set_robust_list() {
    // TODO(Shaohua): Not implemented.
}

pub fn set_thread_area() {
    // TODO(Shaohua): Not implemented.
}

pub fn set_tid_address() {
    // TODO(Shaohua): Not implemented.
}

/// Set NIS domain name.
pub fn setdomainname(name: &str) -> Result<(), Errno> {
    unsafe {
        let name = CString::new(name);
        let name_ptr = name.as_ptr() as usize;
        let name_len = name.len() as usize;
        return syscall2(SYS_SETDOMAINNAME, name_ptr, name_len)
            .map(|_ret| ());
    }
}

/// Set group identify used for filesystem checkes.
pub fn setfsgid(fsgid: gid_t) -> Result<gid_t, Errno> {
    unsafe {
        let fsgid = fsgid as usize;
        return syscall1(SYS_SETFSGID, fsgid)
            .map(|ret| ret as gid_t);
    }
}

/// Set user identify used for filesystem checkes.
pub fn setfsuid(fsuid: uid_t) -> Result<uid_t, Errno> {
    unsafe {
        let fsuid = fsuid as usize;
        return syscall1(SYS_SETFSUID, fsuid)
            .map(|ret| ret as uid_t);
    }
}

/// Set the group ID of the calling process to `gid`.
pub fn setgid(gid: gid_t) -> Result<(), Errno> {
    unsafe {
        let gid = gid as usize;
        return syscall1(SYS_SETGID, gid)
            .map(|_ret| ());
    }
}

/// Set list of supplementary group Ids.
pub fn setgroups(group_list: &[gid_t]) -> Result<(), Errno> {
    unsafe {
        let group_ptr = group_list.as_ptr() as usize;
        let group_len = group_list.len();
        return syscall2(SYS_SETGROUPS, group_ptr, group_len)
            .map(|_ret| ());
    }
}

/// Set hostname
pub fn sethostname(name: &str) -> Result<(), Errno> {
    unsafe {
        let name_ptr = name.as_ptr() as usize;
        let name_len = name.len();
        return syscall2(SYS_SETHOSTNAME, name_ptr, name_len)
            .map(|_ret| ());
    }
}

/// Set value of an interval timer.
pub fn setitimer(which: i32, new_val: &itimerval_t,
                 old_val: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let new_val_ptr = new_val as *const itimerval_t as usize;
        let old_val_ptr = old_val as *mut itimerval_t as usize;
        return syscall3(SYS_SETITIMER, which, new_val_ptr, old_val_ptr)
            .map(|_ret| ());
    }
}

/// Reassociate thread with a namespace.
pub fn setns(fd: i32, nstype: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        let nstype = nstype as usize;
        return syscall2(SYS_SETNS, fd, nstype)
            .map(|_ret| ());
    }
}

/// Set the process group ID (PGID) of the process specified by `pid` to `pgid`.
pub fn setpgid(pid: pid_t, pgid: pid_t) -> Result<(), Errno> {
    unsafe {
        let pid = pid as usize;
        let pgid = pgid as usize;
        return syscall2(SYS_SETPGID, pid, pgid)
            .map(|_ret| ());
    }
}

pub fn setpriority(which: i32, who: i32, prio: i32) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let who = who as usize;
        let prio = prio as usize;
        return syscall3(SYS_SETPRIORITY, which, who, prio)
            .map(|_ret| ());
    }
}

/// Set real and effective group IDs of the calling process.
pub fn setregid(rgid: gid_t, egid: gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid = rgid as usize;
        let egid = egid as usize;
        return syscall2(SYS_SETREGID, rgid, egid)
            .map(|_ret| ());
    }
}


/// Set real and effective user IDs of the calling process.
pub fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid = ruid as usize;
        let euid = euid as usize;
        return syscall2(SYS_SETREUID, ruid, euid)
            .map(|_ret| ());
    }
}

/// Set real, effective and saved group Ids of the calling process.
pub fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<(), Errno> {
    unsafe {
        let rgid = rgid as usize;
        let egid = egid as usize;
        let sgid = sgid as usize;
        return syscall3(SYS_SETREUID, rgid, egid, sgid)
            .map(|_ret| ());
    }
}

/// Set real, effective and saved user Ids of the calling process.
pub fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<(), Errno> {
    unsafe {
        let ruid = ruid as usize;
        let euid = euid as usize;
        let suid = suid as usize;
        return syscall3(SYS_SETREUID, ruid, euid, suid)
            .map(|_ret| ());
    }
}

/// Set resource limit
pub fn setrlimit(resource: u32, rlimit: &rlimit_t) -> Result<(), Errno> {
    unsafe {
        let resource = resource as usize;
        let rlimit_ptr = rlimit as *const rlimit_t as usize;
        return syscall2(SYS_SETRLIMIT, resource, rlimit_ptr)
            .map(|_ret| ());
    }
}

/// Create a new session if the calling process is not a process group leader.
pub fn setsid() -> Result<pid_t, Errno> {
    unsafe {
        return syscall0(SYS_SETSID)
            .map(|ret| ret as pid_t);
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
        return syscall5(SYS_SETSOCKOPT, sockfd, level, optname, optval, optlen)
            .map(|_ret| ());
    }
}

/// Set system time and timezone.
pub fn settimeofday(timeval: &timeval_t, tz: &timezone_t) -> Result<(), Errno> {
    unsafe {
        let timeval_ptr = timeval as *const timeval_t as usize;
        let tz_ptr = tz as *const timezone_t as usize;
        return syscall2(SYS_SETTIMEOFDAY, timeval_ptr, tz_ptr)
            .map(|_ret| ());
    }
}

/// Set the effective user ID of the calling process to `uid`.
pub fn setuid(uid: uid_t) -> Result<(), Errno> {
    unsafe {
        let uid = uid as usize;
        return syscall1(SYS_SETUID, uid)
            .map(|_ret| ());
    }
}

/// Set extended attribute value.
pub fn setxattr(filename: &str, name: &str, value: usize, size: size_t) -> Result<ssize_t, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let name_ptr = name.as_ptr() as usize;
        let size = size as usize;
        return syscall4(SYS_SETXATTR, filename_ptr, name_ptr, value, size)
            .map(|ret| ret as ssize_t);
    }
}

/// Attach the System V shared memory segment.
pub fn shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> Result<usize, Errno> {
    unsafe {
        let shmid = shmid as usize;
        let shmflg = shmflg as usize;
        return syscall3(SYS_SHMAT, shmid, shmaddr, shmflg);
    }
}

/// Detach the System V shared memory segment.
pub fn shmdt(shmaddr: usize) -> Result<(), Errno> {
    unsafe {
        return syscall1(SYS_SHMDT, shmaddr)
            .map(|_ret| ());
    }
}

/// System V shared memory control.
pub fn shmctl(shmid: i32, cmd: i32, buf: &mut shmid_ds) -> Result<i32, Errno> {
    unsafe {
        let shmid = shmid as usize;
        let cmd = cmd as usize;
        let buf_ptr = buf as *mut shmid_ds as usize;
        return syscall3(SYS_SHMCTL, shmid, cmd, buf_ptr)
            .map(|ret| ret as i32);
    }
}

/// Allocates a System V shared memory segment.
pub fn shmget(key: key_t, size: size_t, shmflg: i32) -> Result<(), Errno> {
    unsafe {
        let key = key as usize;
        let size = size as usize;
        let shmflg = shmflg as usize;
        return syscall3(SYS_SHMGET, key, size, shmflg)
            .map(|_ret| ());
    }
}

/// Shutdown part of a full-duplex connection.
pub fn shutdown(sockfd: i32, how: i32) -> Result<(), Errno> {
    unsafe {
        let sockfd = sockfd as usize;
        let how = how as usize;
        return syscall2(SYS_SHUTDOWN, sockfd, how)
            .map(|_ret| ());
    }
}

/// Get/set signal stack context.
pub fn sigaltstack(uss: &sigaltstack_t, uoss: &mut sigaltstack_t) -> Result<(), Errno> {
    unsafe {
        let uss_ptr = uss as *const sigaltstack_t as usize;
        let uoss_ptr = uoss as *mut sigaltstack_t as usize;
        return syscall2(SYS_SIGALTSTACK, uss_ptr, uoss_ptr)
            .map(|_ret| ());
    }
}

/// Create a file descriptor to accept signals.
pub fn signalfd(fd: i32, mask: &[sigset_t]) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let mask_ptr = mask.as_ptr() as usize;
        let mask_len = mask.len() as usize;
        return syscall3(SYS_SIGNALFD, fd, mask_ptr, mask_len)
            .map(|ret| ret as i32);
    }
}

/// Create a file descriptor to accept signals.
pub fn signalfd4(fd: i32, mask: &[sigset_t], flags: i32) -> Result<i32, Errno> {
    unsafe {
        let fd = fd as usize;
        let mask_ptr = mask.as_ptr() as usize;
        let mask_len = mask.len() as usize;
        let flags = flags as usize;
        return syscall4(SYS_SIGNALFD4, fd, mask_ptr, mask_len, flags)
            .map(|ret| ret as i32);
    }
}

/// Create an endpoint for communication.
pub fn socket(domain: i32, sock_type: i32, protocol: i32) -> Result<i32, Errno> {
    unsafe {
        let domain = domain as usize;
        let sock_type = sock_type as usize;
        let protocol = protocol as usize;
        return syscall3(SYS_SOCKET, domain, sock_type, protocol)
            .map(|ret| ret as i32);
    }
}

/// Create a pair of connected socket.
pub fn socketpair(domain: i32, type_: i32, protocol: i32, sv: [i32; 2]) -> Result<(), Errno> {
    unsafe {
        let domain = domain as usize;
        let type_ = type_ as usize;
        let protocol = protocol as usize;
        let sv_ptr = sv.as_ptr() as usize;
        return syscall4(SYS_SOCKETPAIR, domain, type_, protocol, sv_ptr)
            .map(|_ret| ());
    }
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
        return syscall6(SYS_SPLICE, fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags)
            .map(|ret| ret as ssize_t);
    }
}

/// Get file status about a file.
pub fn stat(filename: &str, statbuf: &mut stat_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let statbuf_ptr = statbuf as *mut stat_t as usize;
        return syscall2(SYS_STAT, filename_ptr, statbuf_ptr)
            .map(|_| ());
    }
}

/// Get file status about a file (extended).
pub fn statx(dirfd: i32, filename: &str, flags: i32, mask: u32, buf: &mut statx_t) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flags = flags as usize;
        let mask = mask as usize;
        let buf_ptr = buf as *mut statx_t as usize;
        return syscall5(SYS_STATX, dirfd, filename_ptr, flags, mask, buf_ptr)
            .map(|_ret| ());
    }
}

/// Get filesystem statistics.
pub fn statfs(filename: &str, buf: &mut statfs_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let buf_ptr = buf as *mut statfs_t as usize;
        return syscall2(SYS_STATFS, filename_ptr, buf_ptr)
            .map(|_ret| ());
    }
}

/// Stop swapping to file/device.
pub fn swapoff(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_SWAPOFF, filename_ptr)
            .map(|_ret| ());
    }
}

/// Start swapping to file/device.
pub fn swapon(filename: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flags = flags as usize;
        return syscall2(SYS_SWAPON, filename_ptr, flags)
            .map(|_ret| ());
    }
}

/// Make a new name for a file.
pub fn symlink(oldname: &str, newname: &str) -> Result<(), Errno> {
    unsafe {
        let oldname_ptr = oldname.as_ptr() as usize;
        let newname_ptr = newname.as_ptr() as usize;
        return syscall2(SYS_SYMLINK, oldname_ptr, newname_ptr)
            .map(|_ret| ());
    }
}

/// Make a new name for a file.
pub fn symlinkat(oldname: &str, newfd: i32, newname: &str) -> Result<(), Errno> {
    unsafe {
        let oldname_ptr = oldname.as_ptr() as usize;
        let newfd = newfd as usize;
        let newname_ptr = newname.as_ptr() as usize;
        return syscall3(SYS_SYMLINKAT, oldname_ptr, newfd, newname_ptr)
            .map(|_ret| ());
    }
}

/// Commit filesystem caches to disk.
pub fn sync() {
    unsafe {
        let _ret = syscall0(SYS_SYNC);
    }
}

/// Commit filesystem cache related to `fd` to disk.
pub fn syncfs(fd: i32) -> Result<(), Errno> {
    unsafe {
        let fd = fd as usize;
        return syscall1(SYS_SYNCFS, fd)
            .map(|_ret| ());
    }
}

/// Sync a file segment to disk
pub fn sync_file_range(fd: i32, offset: off_t, nbytes: off_t, flags: i32) -> Result<(), Errno>{
    unsafe {
        let fd = fd as usize;
        let offset = offset as usize;
        let nbytes = nbytes as usize;
        let flags = flags as usize;
        return syscall4(SYS_SYNC_FILE_RANGE, fd, offset, nbytes, flags)
            .map(|_ret| ());
    }
}

/// Read/write system parameters.
pub fn sysctl(args: &mut sysctl_args_t) -> Result<(), Errno> {
    unsafe {
        let args_ptr = args as *mut sysctl_args_t as usize;
        return syscall1(SYS__SYSCTL, args_ptr)
            .map(|_ret| ());
    }
}

/// Get filesystem type information.
pub fn sysfs(option: i32, arg1: usize, arg2: usize) -> Result<i32, Errno> {
    unsafe {
        let option = option as usize;
        let arg1 = arg1 as usize;
        let arg2 = arg2 as usize;
        return syscall3(SYS_SYSFS, option, arg1, arg2)
            .map(|ret| ret as i32);
    }
}

/// Return system information.
pub fn sysinfo(info: &mut sysinfo_t) -> Result<(), Errno> {
    unsafe {
        let info_ptr = info as *mut sysinfo_t as usize;
        return syscall1(SYS_SYSINFO, info_ptr)
            .map(|_ret| ());
    }
}

/// Read and/or clear kernel message ring buffer; set console_loglevel
pub fn syslog(action: i32, buf: &mut str) -> Result<i32, Errno> {
    unsafe {
        let action = action as usize;
        let buf_ptr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();
        return syscall3(SYS_SYSLOG, action, buf_ptr, buf_len)
            .map(|ret| ret as i32);
    }
}

/// Duplicate pipe content.
pub fn tee(fd_in: i32, fd_out: i32, len: size_t, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd_in = fd_in as usize;
        let fd_out = fd_out as usize;
        let len = len as usize;
        let flags = flags as usize;
        return syscall4(SYS_TEE, fd_in, fd_out, len, flags)
            .map(|ret| ret as ssize_t);
    }
}

/// Get time in seconds.
pub fn time() -> Result<time_t, Errno> {
    unsafe {
        return syscall0(SYS_TIME)
            .map(|ret| ret as time_t);
    }
}

pub fn timer_create() {
    // TODO(Shaohua): Not implemented
}

pub fn timer_delete() {
    // TODO(Shaohua): Not implemented
}

pub fn timer_getoverrun() {
    // TODO(Shaohua): Not implemented
}

pub fn timer_gettime() {
    // TODO(Shaohua): Not implemented
}

pub fn timer_settime() {
    // TODO(Shaohua): Not implemented
}

/// Create a timer that notifies via a file descriptor.
pub fn timerfd_create(clockid: i32, flags: i32) -> Result<i32, Errno> {
    unsafe {
        let clockid = clockid as usize;
        let flags = flags as usize;
        return syscall2(SYS_TIMERFD_CREATE, clockid, flags)
            .map(|ret| ret as i32);
    }
}

/// Get current timer via a file descriptor.
pub fn timerfd_gettime(ufd: i32, otmr: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let ufd = ufd as usize;
        let otmr_ptr = otmr as *mut itimerval_t as usize;
        return syscall2(SYS_TIMERFD_GETTIME, ufd, otmr_ptr)
            .map(|_ret| ());
    }
}

/// Set current timer via a file descriptor.
pub fn timerfd_settime(ufd: i32, flags: i32, utmr: &itimerval_t, otmr: &mut itimerval_t) -> Result<(), Errno> {
    unsafe {
        let ufd = ufd as usize;
        let flags = flags as usize;
        let utmr_ptr = utmr as *const itimerval_t as usize;
        let otmr_ptr = otmr as *mut itimerval_t as usize;
        return syscall4(SYS_TIMERFD_SETTIME, ufd, flags, utmr_ptr, otmr_ptr)
            .map(|_ret| ());
    }
}

/// Get process times.
pub fn times(buf: &mut tms_t) -> Result<clock_t, Errno> {
    unsafe {
        let buf_ptr = buf as *mut tms_t as usize;
        return syscall1(SYS_TIMES, buf_ptr)
            .map(|ret| ret as clock_t);
    }
}

/// Truncate a file to a specified length.
pub fn truncate(filename: &str, length: off_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let length = length as usize;
        return syscall2(SYS_TRUNCATE, filename_ptr, length)
            .map(|_ret| ());
    }
}

/// Send a signal to a thread.
pub fn tgkill(tgid: i32, tid: i32, sig: i32) -> Result<(), Errno> {
    unsafe {
        let tgid = tgid as usize;
        let tid = tid as usize;
        let sig = sig as usize;
        return syscall3(SYS_TGKILL, tgid, tid, sig)
            .map(|_ret| ());
    }
}

/// Send a signal to a thread (obsolete).
pub fn tkill(tid: i32, sig: i32) -> Result<(), Errno> {
    unsafe {
        let tid = tid as usize;
        let sig = sig as usize;
        return syscall2(SYS_TKILL, tid, sig)
            .map(|_ret| ());
    }
}

/// Create a child process and wait until it is terminated.
pub fn vfork() -> Result<pid_t, Errno> {
    unsafe {
        return syscall0(SYS_VFORK)
            .map(|ret| ret as pid_t);
    }
}

/// Virtually hang up the current terminal.
pub fn vhangup() -> Result<(), Errno> {
    unsafe {
        return syscall0(SYS_VHANGUP)
            .map(|_ret| ());
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
        return syscall4(SYS_WAIT4, pid, wstatus_ptr, options, rusage_ptr)
            .map(|_ret| ());
    }
}

/// Wait for process to change state
pub fn waitid(which: i32, pid: pid_t, info: &mut siginfo_t, options: i32, ru: &mut rusage_t) -> Result<(), Errno> {
    unsafe {
        let which = which as usize;
        let pid = pid as usize;
        let info_ptr = info as *mut siginfo_t as usize;
        let options = options as usize;
        let ru_ptr = ru as *mut rusage_t as usize;
        return syscall5(SYS_WAITID, which, pid, info_ptr, options, ru_ptr)
            .map(|_ret| ());
    }
}

/// Write to a file descriptor.
pub fn write(fd: i32, buf: &[u8]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let buf_ptr = buf.as_ptr() as usize;
        let len = buf.len() as usize;
        return syscall3(SYS_WRITE, fd, buf_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Write to a file descriptor from multiple buffers.
pub fn writev(fd: i32, iov: &[iovec_t]) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov.as_ptr() as usize;
        let len = iov.len() as usize;
        return syscall3(SYS_WRITE, fd, iov_ptr, len)
            .map(|ret| ret as ssize_t);
    }
}

/// Set file mode creation mask.
pub fn umask(mode: mode_t) -> Result<mode_t, Errno> {
    unsafe {
        let mode = mode as usize;
        return syscall1(SYS_UMASK, mode)
            .map(|ret| ret as mode_t);
    }
}

/// Umount filesystem.
pub fn umount2(name: &str, flags: i32) -> Result<(), Errno> {
    unsafe {
        let name_ptr = name.as_ptr() as usize;
        let flags = flags as usize;
        return syscall2(SYS_UMOUNT2, name_ptr, flags)
            .map(|_ret| ());
    }
}

/// Get name and information about current kernel.
pub fn uname(buf: &mut utsname_t) -> Result<(), Errno> {
    unsafe {
        let buf_ptr = buf as *mut utsname_t as usize;
        return syscall1(SYS_UNAME, buf_ptr)
            .map(|_ret| ());
    }
}

/// Delete a name and possibly the file it refers to.
pub fn unlink(filename: &str) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        return syscall1(SYS_UNLINK, filename_ptr)
            .map(|_ret| ());
    }
}

/// Delete a name and possibly the file it refers to.
pub fn unlinkat(dfd: i32, filename: &str, flag: i32) -> Result<(), Errno> {
    unsafe {
        let dfd = dfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flag = flag as usize;
        return syscall3(SYS_UNLINKAT, dfd, filename_ptr, flag)
            .map(|_ret| ());
    }
}

/// Disassociate parts of the process execution context
pub fn unshare(flags: i32) -> Result<(), Errno> {
    unsafe {
        let flags = flags as usize;
        return syscall1(SYS_UNSHARE, flags)
            .map(|_ret| ());
    }
}

/// Load shared library.
pub fn uselib(library: &str) -> Result<(), Errno> {
    unsafe {
        let library_ptr = library.as_ptr() as usize;
        return syscall1(SYS_USELIB, library_ptr)
            .map(|_ret| ());
    }
}

/// Create a file descriptor to handle page faults in user space.
pub fn userfaultfd(flags: i32) -> Result<i32, Errno> {
    unsafe {
        let flags = flags as usize;
        return syscall1(SYS_USERFAULTFD, flags)
            .map(|ret| ret as i32);
    }
}

/// Get filesystem statistics
pub fn ustat(dev: dev_t, ubuf: &mut ustat_t) -> Result<(), Errno> {
    unsafe {
        let dev = dev as usize;
        let ubuf_ptr = ubuf as *mut ustat_t as usize;
        return syscall2(SYS_USTAT, dev, ubuf_ptr)
            .map(|_ret| ());
    }
}

/// Change file last access and modification time.
pub fn utime(filename: &str, times: &utimbuf_t) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let times_ptr = times as *const utimbuf_t as usize;
        return syscall2(SYS_UTIME, filename_ptr, times_ptr)
            .map(|_ret| ());
    }
}

/// Change file last access and modification time.
pub fn utimes(filename: &str, times: &[timeval_t; 2]) -> Result<(), Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let times_ptr = times.as_ptr() as usize;
        return syscall2(SYS_UTIMES, filename_ptr, times_ptr)
            .map(|_ret| ());
    }
}

/// Change time timestamps with nanosecond precision.
pub fn utimensat(dirfd: i32, filename: &str, times: &[timespec_t; 2], flags: i32) -> Result<(), Errno> {
    unsafe {
        let dirfd = dirfd as usize;
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let times_ptr = times.as_ptr() as usize;
        let flags = flags as usize;
        return syscall4(SYS_UTIMENSAT, dirfd, filename_ptr, times_ptr, flags)
            .map(|_ret| ());
    }
}

/// Splice user page into a pipe.
pub fn vmsplice(fd: i32, iov: &iovec_t, nr_segs: usize, flags: u32) -> Result<ssize_t, Errno> {
    unsafe {
        let fd = fd as usize;
        let iov_ptr = iov as *const iovec_t as usize;
        let flags = flags as usize;
        return syscall4(SYS_VMSPLICE, fd, iov_ptr, nr_segs, flags)
            .map(|ret| ret as ssize_t);
    }
}


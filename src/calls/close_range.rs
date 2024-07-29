/// Close all file descriptors in a given range
///
/// # Examples
///
/// ```
/// const STDOUT_FD: u32 = 1;
/// const STDERR_FD: u32 = 2;
/// let ret = unsafe { nc::close_range(STDOUT_FD, STDERR_FD, nc::CLOSE_RANGE_CLOEXEC) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn close_range(first_fd: u32, last_fd: u32, flags: u32) -> Result<(), Errno> {
    let first = first_fd as usize;
    let last = last_fd as usize;
    let flags = flags as usize;
    syscall3(SYS_CLOSE_RANGE, first, last, flags).map(drop)
}

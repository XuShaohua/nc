/// Read from a file descriptor without changing file offset.
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [0_u8; 128];
/// let read_count = 64;
/// let ret = unsafe { nc::pread(fd, buf.as_mut_ptr() as usize, read_count, 0) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(read_count as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pread(fd: i32, buf: usize, count: usize, offset: off_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let offset = offset as usize;
    syscall4(SYS_PREAD, fd, buf, count, offset).map(|ret| ret as ssize_t)
}

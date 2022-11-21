/// Write to a file descriptor without changing file offset.
///
/// # Example
///
/// ```
/// let path = "/tmp/nc-pwrite64";
/// let ret = unsafe { nc::openat(nc::AT_FDCWD, path, nc::O_WRONLY | nc::O_CREAT, 0o644) };
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let buf = "Hello, Rust";
/// let ret = unsafe { nc::pwrite64(fd, buf.as_ptr() as usize, buf.len(), 0) };
/// assert!(ret.is_ok());
/// assert_eq!(ret, Ok(buf.len() as nc::ssize_t));
/// let ret = unsafe { nc::close(fd) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn pwrite64(
    fd: i32,
    buf: usize,
    count: size_t,
    offset: off_t,
) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let offset = offset as usize;
    syscall4(SYS_PWRITE64, fd, buf, count, offset).map(|ret| ret as ssize_t)
}

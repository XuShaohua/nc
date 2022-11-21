/// Get current working directory.
///
/// # Example
///
/// ```
/// let mut buf = [0_u8; nc::PATH_MAX as usize + 1];
/// let ret = unsafe { nc::getcwd(buf.as_mut_ptr() as usize, buf.len()) };
/// assert!(ret.is_ok());
/// // Remove null-terminal char.
/// let path_len = ret.unwrap() as usize - 1;
/// let cwd = std::str::from_utf8(&buf[..path_len]);
/// assert!(cwd.is_ok());
/// ```
pub unsafe fn getcwd(buf: usize, size: size_t) -> Result<ssize_t, Errno> {
    syscall2(SYS_GETCWD, buf, size).map(|ret| ret as ssize_t)
}

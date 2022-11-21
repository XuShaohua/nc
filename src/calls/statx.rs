/// Get file status about a file (extended).
///
/// # Example
///
/// ```
/// let path = "/etc/passwd";
/// let mut statx = nc::statx_t::default();
/// let ret = unsafe { nc::statx(nc::AT_FDCWD, path, nc::AT_SYMLINK_NOFOLLOW, nc::STATX_TYPE, &mut statx) };
/// assert!(ret.is_ok());
/// // Check fd is a regular file.
/// assert_eq!((statx.stx_mode as u32 & nc::S_IFMT), nc::S_IFREG);
/// ```
pub unsafe fn statx<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    flags: i32,
    mask: u32,
    buf: &mut statx_t,
) -> Result<(), Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flags = flags as usize;
    let mask = mask as usize;
    let buf_ptr = buf as *mut statx_t as usize;
    syscall5(SYS_STATX, dirfd, filename_ptr, flags, mask, buf_ptr).map(drop)
}

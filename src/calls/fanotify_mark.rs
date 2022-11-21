/// Add, remove, or modify an fanotify mark on a filesystem object
pub unsafe fn fanotify_mark<P: AsRef<Path>>(
    fanotify_fd: i32,
    flags: u32,
    mask: u64,
    fd: i32,
    filename: P,
) -> Result<(), Errno> {
    let fanotify_fd = fanotify_fd as usize;
    let flags = flags as usize;
    let mask = mask as usize;
    let fd = fd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    syscall5(
        SYS_FANOTIFY_MARK,
        fanotify_fd,
        flags,
        mask,
        fd,
        filename_ptr,
    )
    .map(drop)
}

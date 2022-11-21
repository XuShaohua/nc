/// Create a file descriptor to accept signals.
pub unsafe fn signalfd4(fd: i32, mask: &[sigset_t], flags: i32) -> Result<i32, Errno> {
    let fd = fd as usize;
    let mask_ptr = mask.as_ptr() as usize;
    let mask_len = mask.len();
    let flags = flags as usize;
    syscall4(SYS_SIGNALFD4, fd, mask_ptr, mask_len, flags).map(|ret| ret as i32)
}

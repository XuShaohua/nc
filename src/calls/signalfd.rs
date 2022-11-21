/// Create a file descriptor to accept signals.
pub unsafe fn signalfd(fd: i32, mask: &[sigset_t]) -> Result<i32, Errno> {
    let fd = fd as usize;
    let mask_ptr = mask.as_ptr() as usize;
    let mask_len = mask.len();
    syscall3(SYS_SIGNALFD, fd, mask_ptr, mask_len).map(|ret| ret as i32)
}

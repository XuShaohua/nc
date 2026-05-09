/// Create a file descriptor to accept signals.
pub unsafe fn signalfd(fd: i32, mask: &sigset_t) -> Result<i32, Errno> {
    let fd = fd as usize;
    let mask_ptr = core::ptr::from_ref(mask) as usize;
    let size_mask = core::mem::size_of::<sigset_t>();
    unsafe { syscall3(SYS_SIGNALFD, fd, mask_ptr, size_mask).map(|ret| ret as i32) }
}

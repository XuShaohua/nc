/// Wait for a signal.
pub unsafe fn sigsuspend(mask: &sigset_t) -> Result<(), Errno> {
    let mask_ptr = mask as *const sigset_t as usize;
    unsafe { syscall1(SYS_SIGSUSPEND, mask_ptr).map(drop) }
}

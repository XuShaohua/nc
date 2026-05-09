/// Wait for a signal.
pub unsafe fn sigsuspend(mask: &sigset_t) -> Result<(), Errno> {
    let mask_ptr = core::ptr::from_ref(mask) as usize;
    unsafe { syscall1(SYS_SIGSUSPEND, mask_ptr).map(drop) }
}

/// Wait for a signal.
pub unsafe fn __sigsuspend14(mask: &sigset_t) -> Result<(), Errno> {
    let mask_ptr = core::ptr::from_ref(mask) as usize;
    unsafe { syscall1(SYS___SIGSUSPEND14, mask_ptr).map(drop) }
}

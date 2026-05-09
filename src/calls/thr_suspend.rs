/// Suspend current thread for some time.
pub unsafe fn thr_suspend(timeout: &timespec_t) -> Result<(), Errno> {
    let timeout_ptr = core::ptr::from_ref(timeout) as usize;
    unsafe { syscall1(SYS_THR_SUSPEND, timeout_ptr).map(drop) }
}

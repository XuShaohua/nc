/// Wait for queued signals (REALTIME)
pub unsafe fn sigtimedwait(
    set: &sigset_t,
    info: &mut siginfo_t,
    timeout: &timespec_t,
) -> Result<i32, Errno> {
    let set_ptr = core::ptr::from_ref(set) as usize;
    let info_ptr = core::ptr::from_mut(info) as usize;
    let timeout_ptr = core::ptr::from_ref(timeout) as usize;
    unsafe { syscall3(SYS_SIGTIMEDWAIT, set_ptr, info_ptr, timeout_ptr).map(|val| val as i32) }
}

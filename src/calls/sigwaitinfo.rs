/// Wait for queued signals (REALTIME)
pub unsafe fn sigwaitinfo(set: &sigset_t, info: &mut siginfo_t) -> Result<i32, Errno> {
    let set_ptr = core::ptr::from_ref(set) as usize;
    let info_ptr = core::ptr::from_mut(info) as usize;
    unsafe { syscall2(SYS_SIGWAITINFO, set_ptr, info_ptr).map(|val| val as i32) }
}

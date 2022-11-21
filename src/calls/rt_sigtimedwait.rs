/// Synchronously wait for queued signals.
pub unsafe fn rt_sigtimedwait(
    uthese: &sigset_t,
    uinfo: &mut siginfo_t,
    uts: &timespec_t,
    sigsetsize: size_t,
) -> Result<i32, Errno> {
    let uthese_ptr = uthese as *const sigset_t as usize;
    let uinfo_ptr = uinfo as *mut siginfo_t as usize;
    let uts_ptr = uts as *const timespec_t as usize;
    syscall4(
        SYS_RT_SIGTIMEDWAIT,
        uthese_ptr,
        uinfo_ptr,
        uts_ptr,
        sigsetsize,
    )
    .map(|ret| ret as i32)
}

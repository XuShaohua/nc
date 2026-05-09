/// Get scheduling paramters.
pub unsafe fn _sched_getparam(
    pid: pid_t,
    lid: lwpid_t,
    policy: &mut i32,
    param: &mut sched_param_t,
) -> Result<(), Errno> {
    let pid = pid as usize;
    let lid = lid as usize;
    let policy_ptr = core::ptr::from_mut(policy) as usize;
    let param_ptr = core::ptr::from_mut(param) as usize;
    unsafe { syscall4(SYS__SCHED_GETPARAM, pid, lid, policy_ptr, param_ptr).map(drop) }
}

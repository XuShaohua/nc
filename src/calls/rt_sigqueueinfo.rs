/// Queue a signal and data.
pub unsafe fn rt_sigqueueinfo(pid: pid_t, sig: i32, uinfo: &mut siginfo_t) -> Result<(), Errno> {
    let pid = pid as usize;
    let sig = sig as usize;
    let uinfo_ptr = uinfo as *mut siginfo_t as usize;
    syscall3(SYS_RT_SIGQUEUEINFO, pid, sig, uinfo_ptr).map(drop)
}

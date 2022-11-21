/// Examine pending signals.
pub unsafe fn rt_sigpending(set: &mut [sigset_t]) -> Result<(), Errno> {
    let set_ptr = set.as_mut_ptr() as usize;
    syscall1(SYS_RT_SIGPENDING, set_ptr).map(drop)
}

/// Change the list of currently blocked signals.
pub unsafe fn rt_sigprocmask(
    how: i32,
    set: &sigset_t,
    oldset: &mut sigset_t,
    sigsetsize: size_t,
) -> Result<(), Errno> {
    let how = how as usize;
    let set_ptr = set as *const sigset_t as usize;
    let oldset_ptr = oldset as *mut sigset_t as usize;
    syscall4(SYS_RT_SIGPROCMASK, how, set_ptr, oldset_ptr, sigsetsize).map(drop)
}

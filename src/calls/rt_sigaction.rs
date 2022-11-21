/// Examine and change a signal action.
///
/// # example
///
/// ```
/// use std::mem::size_of;
///
/// fn handle_sigterm(sig: i32) {
///     assert_eq!(sig, nc::SIGTERM);
/// }
///
/// let sa = nc::sigaction_t {
///     sa_handler: handle_sigterm as nc::sighandler_t,
///     sa_mask: nc::SA_RESTART | nc::SA_SIGINFO | nc::SA_ONSTACK,
///     ..nc::sigaction_t::default()
/// };
/// let mut old_sa = nc::sigaction_t::default();
/// let ret = unsafe { nc::rt_sigaction(nc::SIGTERM, &sa, &mut old_sa, size_of::<nc::sigset_t>()) };
/// let ret = unsafe { nc::kill(nc::getpid(), nc::SIGTERM) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn rt_sigaction(
    sig: i32,
    act: &sigaction_t,
    old_act: &mut sigaction_t,
    sigsetsize: size_t,
) -> Result<(), Errno> {
    let sig = sig as usize;
    let act_ptr = act as *const sigaction_t as usize;
    let old_act_ptr = old_act as *mut sigaction_t as usize;
    syscall4(SYS_RT_SIGACTION, sig, act_ptr, old_act_ptr, sigsetsize).map(drop)
}

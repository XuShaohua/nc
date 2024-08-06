/// Examine and change a signal action.
///
/// # Examples
///
/// ```
/// fn handle_sigterm(sig: i32) {
///     assert_eq!(sig, nc::SIGTERM);
/// }
///
/// #[cfg(nc_has_sa_restorer)]
/// let sa = nc::sigaction_t {
///     sa_handler: handle_sigterm as nc::sighandler_t,
///     sa_flags: nc::SA_RESTORER | nc::SA_RESTART,
///     sa_restorer: nc::restore::get_sa_restorer(),
///     ..nc::sigaction_t::default()
/// };
/// #[cfg(not(nc_has_sa_restorer))]
/// let sa = nc::sigaction_t {
///     sa_handler: handle_sigterm as nc::sighandler_t,
///     sa_flags: nc::SA_RESTART,
///     ..nc::sigaction_t::default()
/// };
/// let ret = unsafe { nc::sigaction(nc::SIGTERM, Some(&sa), None) };
/// let ret = unsafe { nc::kill(nc::getpid(), nc::SIGTERM) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sigaction(
    sig: i32,
    act: Option<&sigaction_t>,
    old_act: Option<&mut sigaction_t>,
) -> Result<(), Errno> {
    let sig = sig as usize;
    let act_ptr = act.map_or(core::ptr::null::<sigaction_t>() as usize, |act| {
        act as *const sigaction_t as usize
    });
    let old_act_ptr = old_act.map_or(core::ptr::null_mut::<sigaction_t>() as usize, |old_act| {
        old_act as *mut sigaction_t as usize
    });
    syscall3(SYS_SIGACTION, sig, act_ptr, old_act_ptr).map(drop)
}

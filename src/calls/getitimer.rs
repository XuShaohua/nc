/// Get value of an interval timer.
///
/// # Examples
///
/// ```
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
///     let msg = b"Hello alarm\n";
///     let stderr = 2;
///     let _ = unsafe { nc::write(stderr, msg) };
/// }
///
/// #[cfg(nc_has_sa_restorer)]
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     sa_flags: nc::SA_RESTORER | nc::SA_RESTART,
///     sa_restorer: nc::restore::get_sa_restorer(),
///     ..nc::sigaction_t::default()
/// };
/// #[cfg(not(nc_has_sa_restorer))]
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     sa_flags: nc::SA_RESTART,
///     ..nc::sigaction_t::default()
/// };
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
/// assert!(ret.is_ok());
///
/// // Single shot timer, actived after 1 second.
/// let itv = nc::itimerval_t {
///     it_value: nc::timeval_t {
///         tv_sec: 1,
///         tv_usec: 0,
///     },
///     it_interval: nc::timeval_t {
///         tv_sec: 0,
///         tv_usec: 0,
///     },
/// };
/// let mut prev_itv = nc::itimerval_t::default();
/// let ret = unsafe { nc::setitimer(nc::ITIMER_REAL, &itv, Some(&mut prev_itv)) };
/// assert!(ret.is_ok());
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);
///
/// let mask = nc::sigset_t::default();
/// let _ret = unsafe { nc::rt_sigsuspend(&mask) };
///
/// let ret = unsafe { nc::getitimer(nc::ITIMER_REAL, &mut prev_itv) };
/// assert!(ret.is_ok());
/// assert_eq!(prev_itv.it_value.tv_sec, 0);
/// assert_eq!(prev_itv.it_value.tv_usec, 0);
/// ```
pub unsafe fn getitimer(which: i32, curr_val: &mut itimerval_t) -> Result<(), Errno> {
    let which = which as usize;
    let curr_val_ptr = curr_val as *mut itimerval_t as usize;
    syscall2(SYS_GETITIMER, which, curr_val_ptr).map(drop)
}

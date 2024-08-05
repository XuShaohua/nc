/// Set an alarm clock for delivery of a signal.
///
/// # Examples
///
/// ```
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
/// }
///
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     sa_flags: nc::SA_RESTORER | nc::SA_RESTART,
///     sa_restorer: nc::restore::get_sa_restorer(),
///     ..nc::sigaction_t::default()
/// };
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
/// assert!(ret.is_ok());
/// let remaining = unsafe { nc::alarm(1) };
/// let mask = nc::sigset_t::default();
/// let ret = unsafe { nc::rt_sigsuspend(&mask) };
/// assert_eq!(ret, Err(nc::EINTR));
/// assert_eq!(remaining, 0);
/// ```
#[must_use]
pub unsafe fn alarm(seconds: u32) -> u32 {
    let seconds = seconds as usize;
    // This function is always successful.
    syscall1(SYS_ALARM, seconds).unwrap_or_default() as u32
}

/// Set an alarm clock for delivery of a signal.
///
/// # Examples
///
/// ```
/// use core::mem::size_of;
///
/// fn handle_alarm(signum: i32) {
///     assert_eq!(signum, nc::SIGALRM);
/// }
///
/// let sa = nc::sigaction_t {
///     sa_handler: handle_alarm as nc::sighandler_t,
///     ..nc::sigaction_t::default()
/// };
/// let mut old_sa = nc::sigaction_t::default();
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>()) };
/// assert!(ret.is_ok());
/// let remaining = unsafe { nc::alarm(1) };
/// let mask = nc::sigset_t::default();
/// let ret = unsafe { nc::rt_sigsuspend(&mask, size_of::<nc::sigset_t>()) };
/// assert_eq!(ret, Err(nc::EINTR));
/// assert_eq!(remaining, 0);
/// ```
#[must_use]
pub unsafe fn alarm(seconds: u32) -> u32 {
    let seconds = seconds as usize;
    // This function is always successful.
    syscall1(SYS_ALARM, seconds).unwrap_or_default() as u32
}

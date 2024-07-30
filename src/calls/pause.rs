/// Pause the calling process to sleep until a signal is delivered.
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
/// let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, &sa, None) };
/// assert!(ret.is_ok());
/// let remaining = unsafe { nc::alarm(1) };
/// let ret = unsafe { nc::pause() };
/// assert!(ret.is_err());
/// assert_eq!(ret, Err(nc::EINTR));
/// assert_eq!(remaining, 0);
/// ```
pub unsafe fn pause() -> Result<(), Errno> {
    syscall0(SYS_PAUSE).map(drop)
}

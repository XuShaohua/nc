/// Get the caller's thread ID (TID).
///
/// # Example
///
/// ```
/// let tid = unsafe { nc::gettid() };
/// assert!(tid > 0);
/// ```
#[must_use]
pub unsafe fn gettid() -> pid_t {
    // This function is always successful.
    syscall0(SYS_GETTID).expect("getpid() failed") as pid_t
}

/// Yield the processor.
///
/// # Examples
///
/// ```
/// let ret = unsafe { nc::sched_yield() };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn sched_yield() -> Result<(), Errno> {
    unsafe { syscall0(SYS_SCHED_YIELD).map(drop) }
}

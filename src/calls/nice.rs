/// Change the priority of current process.
///
/// # Example
///
/// ```
/// let ret = unsafe { nc::nice(5) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn nice(increment: i32) -> Result<(), Errno> {
    let increment = increment as usize;
    syscall1(SYS_NICE, increment).map(drop)
}

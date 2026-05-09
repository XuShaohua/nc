/// Examine and change blocked signals.
pub unsafe fn sigprocmask(
    how: i32,
    newset: &mut sigset_t,
    oldset: &mut sigset_t,
) -> Result<(), Errno> {
    let how = how as usize;
    let newset_ptr = core::ptr::from_mut(newset) as usize;
    let oldset_ptr = core::ptr::from_mut(oldset) as usize;
    unsafe { syscall3(SYS_SIGPROCMASK, how, newset_ptr, oldset_ptr).map(drop) }
}

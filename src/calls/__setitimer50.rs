/// Set value of an interval timer.
pub unsafe fn __setitimer50(
    which: i32,
    new_val: &itimerval_t,
    old_val: &mut itimerval_t,
) -> Result<(), Errno> {
    let which = which as usize;
    let new_val_ptr = core::ptr::from_ref(new_val) as usize;
    let old_val_ptr = core::ptr::from_mut(old_val) as usize;
    unsafe { syscall3(SYS___SETITIMER50, which, new_val_ptr, old_val_ptr).map(drop) }
}

/// Examine pending signals.
pub unsafe fn __sigpending14(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = core::ptr::from_mut(set) as usize;
    unsafe { syscall1(SYS___SIGPENDING14, set_ptr).map(drop) }
}

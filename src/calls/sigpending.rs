/// Examine pending signals.
pub unsafe fn sigpending(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = core::ptr::from_mut(set) as usize;
    unsafe { syscall1(SYS_SIGPENDING, set_ptr).map(drop) }
}

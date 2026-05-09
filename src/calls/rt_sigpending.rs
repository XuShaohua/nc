/// Examine pending signals.
pub unsafe fn rt_sigpending(set: &mut sigset_t) -> Result<(), Errno> {
    let set_ptr = core::ptr::from_mut(set) as usize;
    let sig_set_size = core::mem::size_of::<sigset_t>();
    unsafe { syscall2(SYS_RT_SIGPENDING, set_ptr, sig_set_size).map(drop) }
}

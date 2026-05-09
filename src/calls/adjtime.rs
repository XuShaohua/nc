/// Correct the time to allow synchronization of the system clock.
pub unsafe fn adjtime(delta: &timeval_t, old_delta: &mut timeval_t) -> Result<(), Errno> {
    let delta_ptr = core::ptr::from_ref(delta) as usize;
    let old_delta_ptr = core::ptr::from_mut(old_delta) as usize;
    unsafe { syscall2(SYS_ADJTIME, delta_ptr, old_delta_ptr).map(drop) }
}

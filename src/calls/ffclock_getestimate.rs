/// Get feed-forward clock estimates.
pub unsafe fn ffclock_getestimate(cest: &mut ffclock_estimate_t) -> Result<(), Errno> {
    let cest_ptr = core::ptr::from_mut(cest) as usize;
    unsafe { syscall1(SYS_FFCLOCK_GETESTIMATE, cest_ptr).map(drop) }
}

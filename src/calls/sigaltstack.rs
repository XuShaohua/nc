/// Get/set signal stack context.
pub unsafe fn sigaltstack(
    ss: Option<&sigaltstack_t>,
    old_ss: Option<&mut sigaltstack_t>,
) -> Result<(), Errno> {
    let ss_ptr = ss.map_or(core::ptr::null::<sigaltstack_t>() as usize, |ss| {
        core::ptr::from_ref(ss) as usize
    });
    let old_ss_ptr = old_ss.map_or(core::ptr::null_mut::<sigaltstack_t>() as usize, |old_ss| {
        core::ptr::from_mut(old_ss) as usize
    });
    unsafe { syscall2(SYS_SIGALTSTACK, ss_ptr, old_ss_ptr).map(drop) }
}

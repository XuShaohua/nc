/// Change the list of currently blocked signals.
pub unsafe fn rt_sigprocmask(
    how: i32,
    set: Option<&sigset_t>,
    oldset: Option<&mut sigset_t>,
) -> Result<(), Errno> {
    let how = how as usize;
    let set_ptr = set.map_or(core::ptr::null::<sigset_t>() as usize, |set| {
        core::ptr::from_ref(set) as usize
    });
    let oldset_ptr = oldset.map_or(core::ptr::null_mut::<sigset_t>() as usize, |oldset| {
        core::ptr::from_mut(oldset) as usize
    });
    let sig_set_size = core::mem::size_of::<sigset_t>();
    unsafe { syscall4(SYS_RT_SIGPROCMASK, how, set_ptr, oldset_ptr, sig_set_size).map(drop) }
}

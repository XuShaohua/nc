/// Arm/disarm state of per-process timer.
pub unsafe fn __timer_settime50(
    timer_id: timer_t,
    flags: i32,
    new_value: &itimerspec_t,
    old_value: Option<&mut itimerspec_t>,
) -> Result<(), Errno> {
    let timer_id = timer_id as usize;
    let flags = flags as usize;
    let new_value_ptr = core::ptr::from_ref(new_value) as usize;
    let old_value_ptr = old_value.map_or(0, |old_value| core::ptr::from_mut(old_value) as usize);
    unsafe {
        syscall4(
            SYS___TIMER_SETTIME50,
            timer_id,
            flags,
            new_value_ptr,
            old_value_ptr,
        )
        .map(drop)
    }
}

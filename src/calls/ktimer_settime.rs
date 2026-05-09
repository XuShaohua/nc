/// Sets the time until the next expiration of the timer.
pub unsafe fn ktimer_settime(
    timer_id: i32,
    flags: i32,
    value: &itimerspec_t,
    ovalue: &mut itimerspec_t,
) -> Result<(), Errno> {
    let timer_id = timer_id as usize;
    let flags = flags as usize;
    let value_ptr = core::ptr::from_ref(value) as usize;
    let ovalue_ptr = core::ptr::from_mut(ovalue) as usize;
    unsafe { syscall4(SYS_KTIMER_SETTIME, timer_id, flags, value_ptr, ovalue_ptr).map(drop) }
}

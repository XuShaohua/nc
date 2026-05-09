/// Create a per-process timer (REALTIME)
pub unsafe fn ktimer_craete(
    clockid: clockid_t,
    evp: &mut sigevent_t,
    timer_id: &mut i32,
) -> Result<(), Errno> {
    let clockid = clockid as usize;
    let evp_ptr = core::ptr::from_mut(evp) as usize;
    let timer_id_ptr = core::ptr::from_mut(timer_id) as usize;
    unsafe { syscall3(SYS_KTIMER_CREATE, clockid, evp_ptr, timer_id_ptr).map(drop) }
}

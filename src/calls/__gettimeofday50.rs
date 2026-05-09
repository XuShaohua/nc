/// Get time.
pub unsafe fn __gettimeofday590(timeval: &mut timeval_t, tz: &mut timezone_t) -> Result<(), Errno> {
    let timeval_ptr = core::ptr::from_mut(timeval) as usize;
    let tz_ptr = core::ptr::from_mut(tz) as usize;
    unsafe { syscall2(SYS___GETTIMEOFDAY50, timeval_ptr, tz_ptr).map(drop) }
}

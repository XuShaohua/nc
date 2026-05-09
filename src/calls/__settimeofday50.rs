/// Set system time and timezone.
pub unsafe fn __settimeofday50(timeval: &timeval_t, tz: &timezone_t) -> Result<(), Errno> {
    let timeval_ptr = core::ptr::from_ref(timeval) as usize;
    let tz_ptr = core::ptr::from_ref(tz) as usize;
    unsafe { syscall2(SYS___SETTIMEOFDAY50, timeval_ptr, tz_ptr).map(drop) }
}

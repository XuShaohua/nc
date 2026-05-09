/// Get time.
///
/// # Examples
///
/// ```
/// let mut tv = nc::timeval_t::default();
/// let mut tz = nc::timezone_t::default();
/// let ret = unsafe { nc::gettimeofday(&mut tv, Some(&mut tz)) };
/// assert!(ret.is_ok());
/// assert!(tv.tv_sec > 1611380386);
/// ```
pub unsafe fn gettimeofday(
    timeval: &mut timeval_t,
    tz: Option<&mut timezone_t>,
) -> Result<(), Errno> {
    let timeval_ptr = core::ptr::from_mut(timeval) as usize;
    let tz_ptr = tz.map_or(core::ptr::null_mut::<timezone_t>() as usize, |tz| {
        core::ptr::from_mut(tz) as usize
    });
    unsafe { syscall2(SYS_GETTIMEOFDAY, timeval_ptr, tz_ptr).map(drop) }
}

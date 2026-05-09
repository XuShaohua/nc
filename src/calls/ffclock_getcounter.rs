/// Retrieve feed-forward counter.
pub unsafe fn ffclock_getcounter(ffcount: &mut ffcounter_t) -> Result<(), Errno> {
    let ffcount_ptr = core::ptr::from_mut(ffcount) as usize;
    unsafe { syscall1(SYS_FFCLOCK_GETCOUNTER, ffcount_ptr).map(drop) }
}

/// Set pointer to thread ID.
///
/// Always returns the caller's thread id.
pub unsafe fn set_tid_address(tid: &mut i32) -> pid_t {
    let tid_ptr = core::ptr::from_mut(tid) as usize;
    // This function is always successful.
    unsafe { syscall1(SYS_SET_TID_ADDRESS, tid_ptr).unwrap_or_default() as pid_t }
}

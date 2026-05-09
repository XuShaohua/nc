/// Set thread-local storage information.
pub unsafe fn set_thread_area(info: &mut user_desc_t) -> Result<(), Errno> {
    let info_ptr = core::ptr::from_mut(info) as usize;
    unsafe { syscall1(SYS_SET_THREAD_AREA, info_ptr).map(drop) }
}

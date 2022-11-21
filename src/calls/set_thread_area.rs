/// Set thread-local storage information.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub unsafe fn set_thread_area(user_desc: &mut user_desc_t) -> Result<(), Errno> {
    let user_desc_ptr = user_desc as *mut user_desc_t as usize;
    syscall1(SYS_SET_THREAD_AREA, user_desc_ptr).map(drop)
}

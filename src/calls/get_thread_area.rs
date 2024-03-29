#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Get thread-local storage information.
pub unsafe fn get_thread_area(user_desc: &mut user_desc_t) -> Result<(), Errno> {
    let user_desc_ptr = user_desc as *mut user_desc_t as usize;
    syscall1(SYS_GET_THREAD_AREA, user_desc_ptr).map(drop)
}

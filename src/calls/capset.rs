/// Set capabilities of thread.
pub unsafe fn capset(hdrp: &mut cap_user_header_t, data: &cap_user_data_t) -> Result<(), Errno> {
    let hdrp_ptr = core::ptr::from_mut(hdrp) as usize;
    let data_ptr = core::ptr::from_ref(data) as usize;
    unsafe { syscall2(SYS_CAPSET, hdrp_ptr, data_ptr).map(drop) }
}

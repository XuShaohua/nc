/// Get capabilities of thread.
pub unsafe fn capget(
    hdrp: &mut cap_user_header_t,
    data: &mut cap_user_data_t,
) -> Result<(), Errno> {
    let hdrp_ptr = core::ptr::from_mut(hdrp) as usize;
    let data_ptr = core::ptr::from_mut(data) as usize;
    unsafe { syscall2(SYS_CAPGET, hdrp_ptr, data_ptr).map(drop) }
}

/// Retrieve audit session ID
pub unsafe fn getauid(auid: &mut au_id_t) -> Result<(), Errno> {
    let auid_ptr = core::ptr::from_mut(auid) as usize;
    unsafe { syscall1(SYS_GETAUID, auid_ptr).map(drop) }
}

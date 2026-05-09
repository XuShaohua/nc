/// Set audit session ID
pub unsafe fn setauid(auid: &mut au_id_t) -> Result<(), Errno> {
    let auid_ptr = core::ptr::from_mut(auid) as usize;
    unsafe { syscall1(SYS_SETAUID, auid_ptr).map(drop) }
}

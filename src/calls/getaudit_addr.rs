/// Retrieve audit session state
pub unsafe fn getaudit_addr(info: &mut auditinfo_addr_t, length: u32) -> Result<(), Errno> {
    let info_ptr = core::ptr::from_mut(info) as usize;
    let length = length as usize;
    unsafe { syscall2(SYS_GETAUDIT_ADDR, info_ptr, length).map(drop) }
}

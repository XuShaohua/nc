/// Retrieve audit session state
pub unsafe fn getaudit(info: &mut auditinfo_t) -> Result<(), Errno> {
    let info_ptr = core::ptr::from_mut(info) as usize;
    unsafe { syscall1(SYS_GETAUDIT, info_ptr).map(drop) }
}

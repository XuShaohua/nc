/// Get real, effect and saved group ID.
///
/// # Examples
///
/// ```
/// let mut rgid = 0;
/// let mut egid = 0;
/// let mut sgid = 0;
/// let ret = unsafe { nc::getresgid(&mut rgid, &mut egid, &mut sgid) };
/// assert!(ret.is_ok());
/// assert!(rgid > 0);
/// assert!(egid > 0);
/// assert!(sgid > 0);
/// ```
pub unsafe fn getresgid(rgid: &mut gid_t, egid: &mut gid_t, sgid: &mut gid_t) -> Result<(), Errno> {
    let rgid_ptr = core::ptr::from_mut(rgid) as usize;
    let egid_ptr = core::ptr::from_mut(egid) as usize;
    let sgid_ptr = core::ptr::from_mut(sgid) as usize;
    unsafe { syscall3(SYS_GETRESGID, rgid_ptr, egid_ptr, sgid_ptr).map(drop) }
}

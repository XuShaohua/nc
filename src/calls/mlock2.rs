/// Lock memory.
///
/// # Example
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let ret = unsafe { nc::mlock2(passwd_buf.as_ptr() as usize, passwd_buf.len(), nc::MCL_CURRENT) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlock2(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    syscall3(SYS_MLOCK2, addr, len, flags).map(drop)
}

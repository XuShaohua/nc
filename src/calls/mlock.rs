/// Lock memory.
///
/// # Examples
///
/// ```
/// let mut passwd_buf = [0_u8; 64];
/// let ret = unsafe { nc::mlock(passwd_buf.as_ptr() as usize, passwd_buf.len()) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mlock(addr: usize, len: size_t) -> Result<(), Errno> {
    syscall2(SYS_MLOCK, addr, len).map(drop)
}

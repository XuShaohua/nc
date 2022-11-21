/// Manipulate disk quotes.
pub unsafe fn quotactl<P: AsRef<Path>>(
    cmd: i32,
    special: P,
    id: qid_t,
    addr: usize,
) -> Result<(), Errno> {
    let cmd = cmd as usize;
    let special = CString::new(special.as_ref());
    let special_ptr = special.as_ptr() as usize;
    let id = id as usize;
    syscall4(SYS_QUOTACTL, cmd, special_ptr, id, addr).map(drop)
}

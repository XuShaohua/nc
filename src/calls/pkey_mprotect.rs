/// Set protection on a region of memory.
pub unsafe fn pkey_mprotect(
    start: usize,
    len: size_t,
    prot: usize,
    pkey: i32,
) -> Result<(), Errno> {
    let pkey = pkey as usize;
    syscall4(SYS_PKEY_MPROTECT, start, len, prot, pkey).map(drop)
}

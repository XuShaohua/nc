/// Remap a virtual memory address
pub unsafe fn mremap(
    addr: usize,
    old_len: size_t,
    new_len: size_t,
    flags: usize,
    new_addr: usize,
) -> Result<usize, Errno> {
    syscall5(SYS_MREMAP, addr, old_len, new_len, flags, new_addr)
}

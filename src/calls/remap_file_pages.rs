/// Create a nonlinear file mapping.
/// Deprecated.
pub unsafe fn remap_file_pages(
    start: usize,
    size: size_t,
    prot: i32,
    pgoff: off_t,
    flags: i32,
) -> Result<(), Errno> {
    let prot = prot as usize;
    let pgoff = pgoff as usize;
    let flags = flags as usize;
    syscall5(SYS_REMAP_FILE_PAGES, start, size, prot, pgoff, flags).map(drop)
}

/// Set file flags.
pub unsafe fn lchflags<P: AsRef<Path>>(path: P, flags: fflags_t) -> Result<(), Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_LCHFLAGS, path_ptr, flags).map(drop) }
}

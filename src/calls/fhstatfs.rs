/// Get filesystem statistics referenced by `fh`.
pub unsafe fn fhstatfs(fh: &fhandle_t, buf: &mut statfs_t) -> Result<(), Errno> {
    let fh_ptr = core::ptr::from_ref(fh) as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall2(SYS_FHSTATFS, fh_ptr, buf_ptr).map(drop) }
}

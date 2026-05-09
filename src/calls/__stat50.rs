/// Get file status about a file.
pub unsafe fn __stat50<P: AsRef<Path>>(filename: P, statbuf: &mut stat_t) -> Result<(), Errno> {
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS___STAT50, filename_ptr, statbuf_ptr).map(drop) }
}

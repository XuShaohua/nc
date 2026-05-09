/// Make a hard link.
pub unsafe fn fhlink<P: AsRef<Path>>(fh: &mut fhandle_t, to: P) -> Result<(), Errno> {
    let fh_ptr = core::ptr::from_mut(fh) as usize;
    let to = CString::new(to.as_ref());
    let to_ptr = to.as_ptr() as usize;
    unsafe { syscall2(SYS_FHLINK, fh_ptr, to_ptr).map(drop) }
}

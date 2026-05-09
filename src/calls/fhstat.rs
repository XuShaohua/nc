/// Get file status referenced by `fh`.
pub unsafe fn fhstat(fh: &fhandle_t, sb: &mut stat_t) -> Result<(), Errno> {
    let fh_ptr = core::ptr::from_ref(fh) as usize;
    let sb_ptr = core::ptr::from_mut(sb) as usize;
    unsafe { syscall2(SYS_FHSTAT, fh_ptr, sb_ptr).map(drop) }
}

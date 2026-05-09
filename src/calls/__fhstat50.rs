/// Get file status referenced by `fh`.
pub unsafe fn __fhstat50(fhp: uintptr_t, fh_size: size_t, sb: &mut stat_t) -> Result<(), Errno> {
    let sb_ptr = core::ptr::from_mut(sb) as usize;
    unsafe { syscall3(SYS___FHSTAT50, fhp, fh_size, sb_ptr).map(drop) }
}

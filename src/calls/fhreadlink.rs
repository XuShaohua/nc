/// Read value of a symbolic link.
pub unsafe fn fhreadlink(fh: &mut fhandle_t, buf: &mut [u8]) -> Result<i32, Errno> {
    let fh_ptr = core::ptr::from_mut(fh) as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    unsafe { syscall2(SYS_FHREADLINK, fh_ptr, buf_ptr).map(|val| val as i32) }
}

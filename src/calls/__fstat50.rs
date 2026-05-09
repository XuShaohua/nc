/// Get file status about a file descriptor.
pub unsafe fn __fstat50(fd: i32, statbuf: &mut stat_t) -> Result<(), Errno> {
    let fd = fd as usize;
    let statbuf_ptr = core::ptr::from_mut(statbuf) as usize;
    unsafe { syscall2(SYS___FSTAT50, fd, statbuf_ptr).map(drop) }
}

/// Change timestamp of a file.
pub unsafe fn futimes<P: AsRef<Path>>(fd: i32, times: &[timeval_t; 2]) -> Result<(), Errno> {
    let fd = fd as usize;
    let times_ptr = times.as_ptr() as usize;
    syscall2(SYS_FUTIMES, fd, filename_ptr, times_ptr).map(drop)
}

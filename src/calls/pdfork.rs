/// Create a child process and returns a process descriptor.
pub unsafe fn pdfork(fd: &mut i32, flags: i32) -> Result<pid_t, Errno> {
    let fd_ptr = core::ptr::from_mut(fd) as usize;
    let flags = flags as usize;
    unsafe { syscall2(SYS_PDFORK, fd_ptr, flags).map(|ret| ret as pid_t) }
}

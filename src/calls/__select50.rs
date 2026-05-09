/// Sychronous I/O multiplexing.
pub unsafe fn __select50(
    nfds: i32,
    readfds: &mut fd_set_t,
    writefds: &mut fd_set_t,
    exceptfds: &mut fd_set_t,
    timeout: &mut timeval_t,
) -> Result<i32, Errno> {
    let nfds = nfds as usize;
    let readfds_ptr = core::ptr::from_mut(readfds) as usize;
    let writefds_ptr = core::ptr::from_mut(writefds) as usize;
    let exceptfds_ptr = core::ptr::from_mut(exceptfds) as usize;
    let timeout_ptr = core::ptr::from_mut(timeout) as usize;
    unsafe {
        syscall5(
            SYS___SELECT50,
            nfds,
            readfds_ptr,
            writefds_ptr,
            exceptfds_ptr,
            timeout_ptr,
        )
        .map(|ret| ret as i32)
    }
}

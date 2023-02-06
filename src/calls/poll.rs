/// Wait for some event on file descriptors.
///
/// ## Return value
/// On success, it returns a nonnegative value which is the number of
/// events in the `fds` whose `revents` fields have been set to a nonzero
/// value.
pub unsafe fn poll(fds: &mut [pollfd_t], timeout: i32) -> Result<i32, Errno> {
    // TODO(Shaohua): Add some unittest
    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len();
    let timeout = timeout as usize;
    syscall3(SYS_POLL, fds_ptr, nfds, timeout).map(|ret| ret as i32)
}

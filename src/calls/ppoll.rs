/// Wait for some event on a file descriptor.
pub unsafe fn ppoll(
    fds: &mut [pollfd_t],
    timeout: &timespec_t,
    sigmask: &sigset_t,
    sigsetsize: size_t,
) -> Result<i32, Errno> {
    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len();
    let timeout_ptr = timeout as *const timespec_t as usize;
    let sigmask_ptr = sigmask as *const sigset_t as usize;
    syscall5(
        SYS_PPOLL,
        fds_ptr,
        nfds,
        timeout_ptr,
        sigmask_ptr,
        sigsetsize,
    )
    .map(|ret| ret as i32)
}

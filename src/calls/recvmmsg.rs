/// Receives multile messages on a socket
pub unsafe fn recvmmsg(
    sockfd: i32,
    msgvec: &mut [mmsghdr_t],
    flags: i32,
    timeout: &mut timespec_t,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let msgvec_ptr = (msgvec as *mut [mmsghdr_t]).cast::<*mut mmsghdr_t>() as usize;
    let vlen = msgvec.len();
    let flags = flags as usize;
    let timeout_ptr = timeout as *mut timespec_t as usize;
    syscall5(SYS_RECVMMSG, sockfd, msgvec_ptr, vlen, flags, timeout_ptr).map(|ret| ret as i32)
}

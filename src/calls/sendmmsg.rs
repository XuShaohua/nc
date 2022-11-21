/// Send multiple messages on a socket
pub unsafe fn sendmmsg(sockfd: i32, msgvec: &mut [mmsghdr_t], flags: i32) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let msgvec_ptr = (msgvec as *mut [mmsghdr_t]).cast::<*mut mmsghdr_t>() as usize;
    let vlen = msgvec.len();
    let flags = flags as usize;
    syscall4(SYS_SENDMMSG, sockfd, msgvec_ptr, vlen, flags).map(|ret| ret as i32)
}

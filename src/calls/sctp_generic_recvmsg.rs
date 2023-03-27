/// Receive a msg from a socket.
pub unsafe fn sctp_generic_recvmsg(
    sockfd: i32,
    iov: &mut [iovec_t],
    from: &mut [sockaddr_t],
    from_len_addr: &mut socklen_t,
    sinfo: &mut sctp_sndrcvinfo_t,
    msg_flags: &mut i32,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let iov_ptr = iov.as_mut_ptr() as usize;
    let iov_len = iov.len();
    let from_ptr = from.as_mut_ptr() as usize;
    let from_len_addr_ptr = from_len_addr as *mut socklen_t as usize;
    let sinfo_ptr = sinfo as *mut sctp_sndrcvinfo_t as usize;
    let msg_flags = msg_flags as usize;
    syscall7(
        SYS_SCTP_GENERIC_RECVMSG,
        sockfd,
        iov_ptr,
        iov_len,
        from_ptr,
        from_len_addr_ptr,
        sinfo_ptr,
        msg_flags,
    )
    .map(|ret| ret as ssize_t)
}

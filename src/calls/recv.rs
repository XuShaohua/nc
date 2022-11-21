/// Receive a datagram from a socket.
pub unsafe fn recv(sockfd: i32, buf: &mut [u8], flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buflen = buf.len();
    let flags = flags as usize;
    syscall4(SYS_RECV, sockfd, buf_ptr, buflen, flags).map(|ret| ret as ssize_t)
}

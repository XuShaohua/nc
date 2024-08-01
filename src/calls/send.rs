/// Send a message on a socket.
pub unsafe fn send(sockfd: i32, buf: &[u8], flags: i32) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_ptr() as usize;
    let len = buf.len();
    let flags = flags as usize;
    syscall4(SYS_SEND, sockfd, buf_ptr, len, flags).map(|ret| ret as ssize_t)
}

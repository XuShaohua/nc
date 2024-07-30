/// Accept a connection on a socket.
///
/// On success, `accept()` return a file descriptor for the accepted socket.
pub unsafe fn accept(
    sockfd: i32,
    addr: *mut sockaddr_t,
    addrlen: &mut socklen_t,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    syscall3(SYS_ACCEPT, sockfd, addr_ptr, addrlen_ptr).map(|val| val as i32)
}

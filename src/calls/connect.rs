/// Initialize a connection on a socket.
pub unsafe fn connect(sockfd: i32, addr: &sockaddr_in_t, addrlen: socklen_t) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    // TODO(Shaohua): Use sockaddr_t generic type.
    let addr_ptr = addr as *const sockaddr_in_t as usize;
    let addrlen = addrlen as usize;
    syscall3(SYS_CONNECT, sockfd, addr_ptr, addrlen).map(drop)
}

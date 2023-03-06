/// Initialize a connection on a socket.
pub unsafe fn connect(
    fd: i32,
    sockfd: i32,
    addr: const* sockaddr_t,
    addrlen: socklen_t,
) -> Result<(), Errno> {
    let fd = fd as usize;
    let sockfd = sockfd as usize;
    let addr_ptr = addr as *const sockaddr_t as usize;
    let addrlen = addrlen as usize;
    syscall4(SYS_CONNECTAT, fd, sockfd, addr_ptr, addrlen).map(drop)
}

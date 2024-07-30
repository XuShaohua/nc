/// Accept a connection on a socket.
pub unsafe fn accept4(
    sockfd: i32,
    addr: *mut sockaddr_t,
    addrlen: &mut socklen_t,
    flags: i32,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = addr as usize;
    let addrlen_ptr = addrlen as *mut socklen_t as usize;
    let flags = flags as usize;
    syscall4(SYS_ACCEPT4, sockfd, addr_ptr, addrlen_ptr, flags).map(|val| val as i32)
}

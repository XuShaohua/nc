/// Accept a connection on a socket.
pub unsafe fn accept_nocancel(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
) -> Result<i32, Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = core::ptr::from_mut(addr) as usize;
    let addrlen_ptr = core::ptr::from_mut(addrlen) as usize;
    unsafe { syscall3(SYS_ACCEPT_NOCANCEL, sockfd, addr_ptr, addrlen_ptr).map(|val| val as i32) }
}

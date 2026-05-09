/// Accept a connection on a socket.
pub unsafe fn paccept(
    sockfd: i32,
    addr: &mut sockaddr_in_t,
    addrlen: &mut socklen_t,
    sigmask: Option<&sigset_t>,
    flags: i32,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let addr_ptr = core::ptr::from_mut(addr) as usize;
    let addrlen_ptr = core::ptr::from_mut(addrlen) as usize;
    let sigmask_ptr = sigmask.map_or(0, |sigmask| core::ptr::from_ref(sigmask) as usize);
    let flags = flags as usize;
    unsafe {
        syscall5(
            SYS_PACCEPT,
            sockfd,
            addr_ptr,
            addrlen_ptr,
            sigmask_ptr,
            flags,
        )
        .map(drop)
    }
}

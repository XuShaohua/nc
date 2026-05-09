/// Get options on sockets
pub unsafe fn getsockopt2(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: *mut usize,
    optlen: &mut socklen_t,
) -> Result<(), Errno> {
    let sockfd = sockfd as usize;
    let level = level as usize;
    let optname = optname as usize;
    let optval_ptr = core::ptr::from_mut(optval) as usize;
    let optlen_ptr = core::ptr::from_mut(optlen) as usize;
    unsafe {
        syscall5(
            SYS_GETSOCKOPT2,
            sockfd,
            level,
            optname,
            optval_ptr,
            optlen_ptr,
        )
        .map(drop)
    }
}

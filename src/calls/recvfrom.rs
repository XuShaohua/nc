/// Receive a message from a socket.
///
/// # Examples
///
/// ```
/// use std::thread;
///
/// const READ_SIDE: usize = 0;
/// const WRITE_SIDE: usize = 1;
///
/// fn main() {
///     let mut fds = [-1_i32; 2];
///
///     let ret = unsafe { nc::socketpair(nc::AF_UNIX, nc::SOCK_STREAM, 0, &mut fds) };
///     assert!(ret.is_ok());
///     println!("socket pairs: {}, {}", fds[0], fds[1]);
///
///     // Start worker thread
///     thread::spawn(move || {
///         println!("worker thread started");
///         let msg = "Hello, Rust";
///         println!("[worker] Will send msg: {msg}");
///         let ret = unsafe { nc::sendto(fds[WRITE_SIDE], msg.as_bytes(), 0, None, 0) };
///         assert!(ret.is_ok());
///         assert_eq!(ret, Ok(msg.len() as nc::ssize_t));
///     });
///
///     let mut buf = [0_u8; 1024];
///     let ret = unsafe { nc::recvfrom(fds[READ_SIDE], &mut buf, 0, None, None) };
///     assert!(ret.is_ok());
///     let nread = ret.unwrap();
///     let msg = std::str::from_utf8(&buf[..nread as usize]).unwrap();
///     println!("[main] recv msg: {msg}");
///
///     unsafe {
///         let _ = nc::close(fds[0]);
///         let _ = nc::close(fds[1]);
///     }
/// }
/// ```
pub unsafe fn recvfrom(
    sockfd: i32,
    buf: &mut [u8],
    flags: i32,
    src_addr: Option<*mut sockaddr_t>,
    addrlen: Option<&mut socklen_t>,
) -> Result<ssize_t, Errno> {
    let sockfd = sockfd as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buflen = buf.len();
    let flags = flags as usize;
    let src_addr_ptr = src_addr.map_or(core::ptr::null_mut::<sockaddr_t>() as usize, |src_addr| {
        src_addr as usize
    });
    let addrlen_ptr = addrlen.map_or(core::ptr::null_mut::<socklen_t>() as usize, |addrlen| {
        addrlen as *mut socklen_t as usize
    });
    syscall6(
        SYS_RECVFROM,
        sockfd,
        buf_ptr,
        buflen,
        flags,
        src_addr_ptr,
        addrlen_ptr,
    )
    .map(|ret| ret as ssize_t)
}

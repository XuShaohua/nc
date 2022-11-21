/// Splice user page into a pipe.
pub unsafe fn vmsplice(
    fd: i32,
    iov: &iovec_t,
    nr_segs: usize,
    flags: u32,
) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    let iov_ptr = iov as *const iovec_t as usize;
    let flags = flags as usize;
    syscall4(SYS_VMSPLICE, fd, iov_ptr, nr_segs, flags).map(|ret| ret as ssize_t)
}

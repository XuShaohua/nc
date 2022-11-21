pub unsafe fn io_uring_enter(
    fd: i32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    sig: &sigset_t,
    sigsetsize: size_t,
) -> Result<i32, Errno> {
    let fd = fd as usize;
    let to_submit = to_submit as usize;
    let min_complete = min_complete as usize;
    let flags = flags as usize;
    let sig_ptr = sig as *const sigset_t as usize;
    syscall6(
        SYS_IO_URING_ENTER,
        fd,
        to_submit,
        min_complete,
        flags,
        sig_ptr,
        sigsetsize,
    )
    .map(|ret| ret as i32)
}

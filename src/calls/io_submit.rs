/// Queue the nr iocbs pointed to by iocbpp for processing.
///
/// Returns the number of iocbs queued.
///
/// # Errors
///
/// - May return `-EINVAL` if the `aio_context` specified by `ctx_id` is invalid,
/// if `nr` is < 0, if the `iocb` at `*iocbpp[0]` is not properly initialized,
/// if the operation specified is invalid for the file descriptor in the `iocb`.
/// - May fail with `-EFAULT` if any of the data structures point to invalid data.
/// - May fail with `-EBADF` if the file descriptor specified in the first
/// `iocb` is invalid.
/// - May fail with `-EAGAIN` if insufficient resources are available to queue any iocbs.
/// - Will return 0 if nr is 0.
/// - Will fail with `-ENOSYS` if not implemented.
// TODO(Shaohua): type of iocbpp is struct iocb**
pub unsafe fn io_submit(ctx_id: aio_context_t, nr: isize, iocb: &mut iocb_t) -> Result<i32, Errno> {
    let nr = nr as usize;
    let iocb_ptr = iocb as *mut iocb_t as usize;
    syscall3(SYS_IO_SUBMIT, ctx_id, nr, iocb_ptr).map(|ret| ret as i32)
}

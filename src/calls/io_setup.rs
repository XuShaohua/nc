/// Create an asynchronous I/O context.
///
/// Create an `aio_context` capable of receiving at least `nr_events`.
/// ctxp must not point to an `aio_context` that already exists, and
/// must be initialized to 0 prior to the call.
///
/// On successful creation of the `aio_context`, `*ctxp` is filled in with the resulting
/// handle.
///
/// # Errors
///
/// - May fail with `-EINVAL` if `*ctxp` is not initialized,
/// if the specified `nr_events` exceeds internal limits.
/// - May fail with `-EAGAIN` if the specified `nr_events` exceeds the user's limit
/// of available events.
/// - May fail with `-ENOMEM` if insufficient kernel resources are available.
/// - May fail with `-EFAULT` if an invalid pointer is passed for ctxp.
/// - Will fail with `-ENOSYS` if not implemented.
pub unsafe fn io_setup(nr_events: u32, ctx_id: &mut aio_context_t) -> Result<(), Errno> {
    let nr_events = nr_events as usize;
    let ctx_id_ptr = ctx_id as *mut aio_context_t as usize;
    syscall2(SYS_IO_SETUP, nr_events, ctx_id_ptr).map(drop)
}

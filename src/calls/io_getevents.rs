/// Attempts to read at least `min_nr` events and up to nr events from
/// the completion queue for the `aio_context` specified by `ctx_id`.
///
/// If it succeeds, the number of read events is returned.
///
/// # Errors
///
/// - May fail with `-EINVAL` if `ctx_id` is invalid, if `min_nr` is out of range,
/// if `nr` is out of range, if `timeout` is out of range.
/// - May fail with `-EFAULT` if any of the memory specified is invalid.
/// - May return 0 or < `min_nr` if the timeout specified by timeout has elapsed
/// before sufficient events are available, where timeout == NULL
/// specifies an infinite timeout. Note that the timeout pointed to by timeout is relative.
/// - Will fail with `-ENOSYS` if not implemented.
pub unsafe fn io_getevents(
    ctx_id: aio_context_t,
    min_nr: isize,
    nr: isize,
    events: &mut io_event_t,
    timeout: &mut timespec_t,
) -> Result<i32, Errno> {
    let min_nr = min_nr as usize;
    let nr = nr as usize;
    let events_ptr = events as *mut io_event_t as usize;
    let timeout_ptr = timeout as *mut timespec_t as usize;
    syscall5(
        SYS_IO_GETEVENTS,
        ctx_id,
        min_nr,
        nr,
        events_ptr,
        timeout_ptr,
    )
    .map(|ret| ret as i32)
}

/// read asynchronous I/O events from the completion queue
pub unsafe fn io_pgetevents(
    ctx_id: aio_context_t,
    min_nr: isize,
    nr: isize,
    events: &mut io_event_t,
    timeout: &mut timespec_t,
    usig: &aio_sigset_t,
) -> Result<i32, Errno> {
    let min_nr = min_nr as usize;
    let nr = nr as usize;
    let events_ptr = events as *mut io_event_t as usize;
    let timeout_ptr = timeout as *mut timespec_t as usize;
    let usig_ptr = usig as *const aio_sigset_t as usize;
    syscall6(
        SYS_IO_PGETEVENTS,
        ctx_id,
        min_nr,
        nr,
        events_ptr,
        timeout_ptr,
        usig_ptr,
    )
    .map(|ret| ret as i32)
}

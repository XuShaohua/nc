/// Wait on a futex.
///
/// - `uaddr`: Address of the futex to wait on
/// - `val`: Value of `uaddr`
/// - `mask`: bitmask
/// - `flags`: `FUTEX2` flags
/// - `timeout`: Optional absolute timeout
/// `clockid`: Clock to be used for the timeout, realtime or monotonic
///
/// Identical to the traditional `FUTEX_WAIT_BITSET` op, except it is part of the
/// futex2 familiy of calls.
pub unsafe fn futex_wait(
    uaddr: *mut (),
    val: usize,
    mask: usize,
    flags: u32,
    timeout: &mut timespec_t,
    clockid: clockid_t,
) -> Result<(), Errno> {
    let uaddr = uaddr as usize;
    let flags = flags as usize;
    let timeout_ptr = timeout as *mut timespec_t as usize;
    let clockid = clockid as usize;
    syscall6(
        SYS_FUTEX_WAIT,
        uaddr,
        val,
        mask,
        flags,
        timeout_ptr,
        clockid,
    )
    .map(drop)
}

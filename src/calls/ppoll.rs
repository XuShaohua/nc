/// Wait for some event on a file descriptor.
pub unsafe fn ppoll(
    fds: &mut [pollfd_t],
    timeout: Option<&timespec_t>,
    sig_mask: Option<&sigset_t>,
) -> Result<i32, Errno> {
    use core::ptr::null;

    let fds_ptr = fds.as_mut_ptr() as usize;
    let nfds = fds.len();
    let timeout_ptr = timeout.map_or(null::<timespec_t>() as usize, |timeout| {
        core::ptr::from_ref(timeout) as usize
    });
    let sig_mask_ptr = sig_mask.map_or(null::<sigset_t>() as usize, |sig_mask| {
        core::ptr::from_ref(sig_mask) as usize
    });
    let sig_set_size = core::mem::size_of::<sigset_t>();
    unsafe {
        syscall5(
            SYS_PPOLL,
            fds_ptr,
            nfds,
            timeout_ptr,
            sig_mask_ptr,
            sig_set_size,
        )
        .map(|ret| ret as i32)
    }
}

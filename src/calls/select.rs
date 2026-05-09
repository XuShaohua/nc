/// Sychronous I/O multiplexing.
pub unsafe fn select(
    nfds: i32,
    read_fds: Option<&mut fd_set_t>,
    write_fds: Option<&mut fd_set_t>,
    except_fds: Option<&mut fd_set_t>,
    timeout: Option<&timeval_t>,
) -> Result<i32, Errno> {
    use core::ptr::{null, null_mut};

    let nfds = nfds as usize;
    let read_fds_ptr = read_fds.map_or(null_mut::<fd_set_t>() as usize, |read_fds| {
        core::ptr::from_mut(read_fds) as usize
    });
    let write_fds_ptr = write_fds.map_or(null_mut::<fd_set_t>() as usize, |write_fds| {
        core::ptr::from_mut(write_fds) as usize
    });
    let except_fds_ptr = except_fds.map_or(null_mut::<fd_set_t>() as usize, |except_fds| {
        core::ptr::from_mut(except_fds) as usize
    });
    let timeout_ptr = timeout.map_or(null::<timeval_t>() as usize, |timeout| {
        core::ptr::from_ref(timeout) as usize
    });
    unsafe {
        syscall5(
            SYS_SELECT,
            nfds,
            read_fds_ptr,
            write_fds_ptr,
            except_fds_ptr,
            timeout_ptr,
        )
        .map(|ret| ret as i32)
    }
}

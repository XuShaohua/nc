/// Get current timer via a file descriptor.
pub unsafe fn timerfd_gettime(ufd: i32, cur_value: &mut itimerspec_t) -> Result<(), Errno> {
    let ufd = ufd as usize;
    let cur_value_ptr = cur_value as *mut itimerspec_t as usize;
    syscall2(SYS_TIMERFD_GETTIME, ufd, cur_value_ptr).map(drop)
}

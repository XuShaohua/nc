/// Signal a process through a pidfd.
///
/// @pidfd:  file descriptor of the process
/// @sig:    signal to send
/// @info:   signal info
/// @flags:  future flags
///
/// The syscall currently only signals via `PIDTYPE_PID` which covers
/// `kill(<positive-pid>, <signal>)`. It does not signal threads or process
/// groups.
/// In order to extend the syscall to threads and process groups the @flags
/// argument should be used. In essence, the @flags argument will determine
/// what is signaled and not the file descriptor itself. Put in other words,
/// grouping is a property of the flags argument not a property of the file
/// descriptor.
///
/// Return: 0 on success, negative errno on failure
pub unsafe fn pidfd_send_signal(
    pidfd: i32,
    sig: i32,
    info: &mut siginfo_t,
    flags: u32,
) -> Result<(), Errno> {
    let pidfd = pidfd as usize;
    let sig = sig as usize;
    let info_ptr = info as *mut siginfo_t as usize;
    let flags = flags as usize;
    syscall4(SYS_PIDFD_SEND_SIGNAL, pidfd, sig, info_ptr, flags).map(drop)
}

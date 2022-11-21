/// New api to create child process.
///
/// # Example
///
/// ```
/// let mut args = nc::clone_args_t::default();
/// let mut pid_fd: i32 = -1;
/// args.exit_signal = nc::SIGCHLD as u64;
/// args.pidfd = &mut pid_fd as *mut i32 as usize as u64;
/// args.flags = nc::CLONE_PIDFD as u64 | nc::CLONE_PARENT_SETTID as u64;
/// let pid = unsafe { nc::clone3(&mut args, core::mem::size_of::<nc::clone_args_t>()) };
/// assert!(pid.is_ok());
/// ```
pub unsafe fn clone3(cl_args: &mut clone_args_t, size: size_t) -> Result<pid_t, Errno> {
    let cl_args_ptr = cl_args as *mut clone_args_t as usize;
    syscall2(SYS_CLONE3, cl_args_ptr, size).map(|ret| ret as pid_t)
}

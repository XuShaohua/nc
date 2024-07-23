fn main() {
    let mut args = nc::clone_args_t::default();
    let mut pid_fd: i32 = -1;
    args.exit_signal = nc::SIGCHLD as u64;
    args.pidfd = &mut pid_fd as *mut i32 as usize as u64;
    args.flags = nc::CLONE_PIDFD as u64 | nc::CLONE_PARENT_SETTID as u64;
    let pid = unsafe { nc::clone3(&mut args) };
    match pid {
        Err(errno) => eprintln!("clone3() failed, err: {:?}", nc::strerror(errno)),
        Ok(0) => println!("[child] pid"),
        Ok(pid) => println!("[parent] pid: {pid:?}"),
    }
    assert!(pid.is_ok());
}

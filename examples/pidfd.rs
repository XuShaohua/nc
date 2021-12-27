const STDOUT_FD: i32 = 1;

fn main() {
    let pid = nc::fork();
    assert!(pid.is_ok());
    if pid == Ok(0) {
        println!("In child process, pid: {}", nc::getpid());
        let path = "/tmp/nc-pidfdopen";
        let fd = nc::openat(
            nc::AT_FDCWD,
            path,
            nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
            0o644,
        );
        assert!(fd.is_ok());
        let fd = fd.unwrap();
        assert!(nc::dup2(fd, STDOUT_FD).is_ok());
        println!("[child] stdout redirected to file!");

        let t = nc::timespec_t {
            tv_sec: 2,
            tv_nsec: 0,
        };
        assert!(nc::nanosleep(&t, None).is_ok());
        let _ = nc::close(fd);
        let _ = nc::unlink(path);
        nc::exit(0);
    }

    let pid = pid.unwrap();
    println!("[parent] child pid: {}", pid);

    let t = nc::timespec_t {
        tv_sec: 2,
        tv_nsec: 0,
    };
    assert!(nc::nanosleep(&t, None).is_ok());

    let pidfd = nc::pidfd_open(pid, 0);
    assert!(pidfd.is_ok());
    let pidfd = pidfd.unwrap();

    let ret = nc::pidfd_getfd(pidfd, STDOUT_FD, 0);
    println!("ret: {:?}", ret);
    if let Err(errno) = ret {
        eprintln!("pidfd_getfd() failed, err: {}", nc::strerror(errno));
    }
    let child_stdout_fd = ret.unwrap();
    let msg = "Hello, msg from parent process\n";
    let ret = nc::write(child_stdout_fd, msg.as_ptr() as usize, msg.len());
    assert!(ret.is_ok());
    let nwrite = ret.unwrap();
    assert_eq!(nwrite as usize, msg.len());

    let mut info = nc::siginfo_t::default();
    let ret = nc::pidfd_send_signal(pidfd, nc::SIGKILL, &mut info, 0);
    println!("ret: {:?}", ret);
    if let Err(errno) = ret {
        eprintln!("pidfd_send_signal() failed, err: {}", nc::strerror(errno));
    }

    let _ = nc::close(pidfd);
    let _ = nc::close(child_stdout_fd);
}

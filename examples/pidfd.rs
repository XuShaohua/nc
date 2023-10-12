// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    run_main();
}

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "loongarch64",
    target_arch = "riscv64"
))]
fn run_main() {}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "loongarch64",
    target_arch = "riscv64"
)))]
fn run_main() {
    const STDOUT_FD: i32 = 1;

    let pid = unsafe { nc::fork() };
    assert!(pid.is_ok());
    if pid == Ok(0) {
        let curr_pid = unsafe { nc::getpid() };
        println!("In child process, pid: {}", curr_pid);
        let path = "/tmp/nc-pidfdopen";
        let fd = unsafe {
            nc::openat(
                nc::AT_FDCWD,
                path,
                nc::O_CREAT | nc::O_WRONLY | nc::O_TRUNC,
                0o644,
            )
        };
        assert!(fd.is_ok());
        let fd = fd.unwrap();
        let ret = unsafe { nc::dup3(fd, STDOUT_FD, 0) };
        assert!(ret.is_ok());
        println!("[child] stdout redirected to file!");

        let t = nc::timespec_t {
            tv_sec: 2,
            tv_nsec: 0,
        };
        unsafe {
            let ret = nc::nanosleep(&t, None);
            assert!(ret.is_ok());
            let ret = nc::close(fd);
            assert!(ret.is_ok());
            let ret = nc::unlinkat(nc::AT_FDCWD, path, 0);
            assert!(ret.is_ok());
            nc::exit(0);
        }
    }

    let pid = pid.unwrap();
    println!("[parent] child pid: {}", pid);

    let t = nc::timespec_t {
        tv_sec: 2,
        tv_nsec: 0,
    };
    let ret = unsafe { nc::nanosleep(&t, None) };
    assert!(ret.is_ok());

    let pidfd = unsafe { nc::pidfd_open(pid, 0) };
    assert!(pidfd.is_ok());
    let pidfd = pidfd.unwrap();

    let ret = unsafe { nc::pidfd_getfd(pidfd, STDOUT_FD, 0) };
    println!("ret: {:?}", ret);
    if let Err(errno) = ret {
        eprintln!("pidfd_getfd() failed, err: {}", nc::strerror(errno));
    }
    let child_stdout_fd = ret.unwrap();
    let msg = "Hello, msg from parent process\n";
    let ret = unsafe { nc::write(child_stdout_fd, msg.as_ptr() as usize, msg.len()) };
    assert!(ret.is_ok());
    let nwrite = ret.unwrap();
    assert_eq!(nwrite as usize, msg.len());

    let mut info = nc::siginfo_t::default();
    let ret = unsafe { nc::pidfd_send_signal(pidfd, nc::SIGKILL, &mut info, 0) };
    println!("ret: {:?}", ret);
    if let Err(errno) = ret {
        eprintln!("pidfd_send_signal() failed, err: {}", nc::strerror(errno));
    }

    unsafe {
        let ret = nc::close(pidfd);
        assert!(ret.is_ok());
        let ret = nc::close(child_stdout_fd);
        assert!(ret.is_ok());
    }
}

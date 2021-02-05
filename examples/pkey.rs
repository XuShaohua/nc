use core::mem::size_of;

fn handle_alarm(signum: i32) {
    assert_eq!(signum, nc::SIGSTOP);
}

fn main() {
    /*
    int real_prot = PROT_READ|PROT_WRITE;
    pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
    ptr = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    ret = pkey_mprotect(ptr, PAGE_SIZE, real_prot, pkey);
    */

    let rights = nc::PKEY_DISABLE_WRITE as usize;
    let ret = nc::pkey_alloc(0, rights);
    println!("error: {}", nc::strerror(ret.unwrap_err()));
    assert!(ret.is_ok());
    let key = ret.unwrap();

    let ret = nc::pkey_free(key);
    assert!(ret.is_ok());

    /*
    let ret = nc::fork();
    assert!(ret.is_ok());
    let pid = ret.unwrap();
    if pid == 0 {
        println!("[child] pid: {}", nc::getpid());
        let sa = nc::sigaction_t {
            sa_handler: handle_alarm as nc::sighandler_t,
            sa_mask: nc::SA_RESTART | nc::SA_SIGINFO | nc::SA_ONSTACK,
            ..nc::sigaction_t::default()
        };
        let mut old_sa = nc::sigaction_t::default();
        let ret = nc::rt_sigaction(nc::SIGSTOP, &sa, &mut old_sa, size_of::<nc::sigset_t>());
        println!("error: {}", nc::strerror(ret.unwrap_err()));
        assert!(ret.is_ok());

        let t = nc::timespec_t {
            tv_sec: 3,
            tv_nsec: 0,
        };
        let mut rem = nc::timespec_t::default();
        let ret = nc::nanosleep(&t, Some(&mut rem));

        println!("ret: {:?}", ret);
        println!("rem: {:?}", rem);
        assert!(ret.is_err());
        let ret = nc::restart_syscall();
        println!("ret: {}", nc::strerror(ret.unwrap_err()));
        nc::exit(0);
    } else {
        println!("[parent] child pid: {}", pid);
        let ret = nc::kill(pid, nc::SIGSTOP);
        assert!(ret.is_ok());

        let t = nc::timespec_t {
            tv_sec: 0,
            tv_nsec: 1000_000,
        };
        let ret = nc::nanosleep(&t, None);
        assert!(ret.is_ok());

        let ret = nc::kill(pid, nc::SIGCONT);
        assert!(ret.is_ok());

        let mut status = 0;
        let mut usage = nc::rusage_t::default();
        let ret = nc::wait4(-1, &mut status, 0, &mut usage);
        assert!(ret.is_ok());
    }
    */
}

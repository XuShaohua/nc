// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[no_mangle]
fn handle_alarm(signum: i32) {
    println!("handle alarm");
    assert_eq!(signum, nc::SIGALRM);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
pub fn alarm(seconds: u32) -> Result<u32, nc::Errno> {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "loongarch64",
        target_arch = "riscv64",
    ))]
    let remaining = {
        let mut it = nc::itimerval_t::default();
        it.it_value.tv_sec = seconds as isize;
        let mut old = nc::itimerval_t::default();
        unsafe { nc::setitimer(nc::ITIMER_REAL, &it, Some(&mut old))? };
        (old.it_value.tv_sec + !!old.it_value.tv_usec) as u32
    };

    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "loongarch64",
        target_arch = "riscv64",
    )))]
    let remaining = { unsafe { nc::alarm(seconds) } };
    Ok(remaining)
}

fn main() {
    let sa = nc::sigaction_t {
        sa_handler: handle_alarm as nc::sighandler_t,
        sa_flags: nc::SA_RESTORER | nc::SA_RESTART,
        sa_restorer: nc::restore::get_sa_restorer(),
        ..nc::sigaction_t::default()
    };
    let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
    assert!(ret.is_ok());

    let seconds = 1;
    let remaining = alarm(seconds);
    let mask = nc::sigset_t::default();
    let ret = unsafe { nc::rt_sigsuspend(&mask) };
    assert!(ret.is_err());
    assert_eq!(ret, Err(nc::EINTR));
    assert_eq!(remaining.unwrap(), 0);
}

// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[no_mangle]
fn handle_alarm(signum: i32) {
    println!("handle alarm");
    assert_eq!(signum, nc::SIGALRM);
}

#[must_use]
#[inline]
fn get_sa_restorer() -> Option<nc::restorefn_t> {
    let mut old_sa = nc::sigaction_t::default();
    let ret = unsafe { nc::rt_sigaction(nc::SIGSEGV, None, Some(&mut old_sa)) };
    if ret.is_ok() {
        old_sa.sa_restorer
    } else {
        None
    }
}

fn main() {
    let sa = nc::sigaction_t {
        sa_handler: handle_alarm as nc::sighandler_t,
        sa_flags: nc::SA_RESTART | nc::SA_RESTORER,
        sa_restorer: get_sa_restorer(),
        ..nc::sigaction_t::default()
    };
    let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, Some(&sa), None) };
    assert!(ret.is_ok());

    let seconds = 1;
    let remaining = nc::util::alarm(seconds);

    let mask = nc::sigset_t::default();
    let ret = unsafe { nc::rt_sigsuspend(&mask) };
    assert!(ret.is_err());
    assert_eq!(ret, Err(nc::EINTR));

    assert_eq!(remaining.unwrap(), 0);
}

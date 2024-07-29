// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use core::mem::{size_of, size_of_val};

#[no_mangle]
fn handle_alarm(signum: i32) {
    println!("handle alarm");
    assert_eq!(signum, nc::SIGALRM);
}

fn main() {
    let sa = nc::sigaction_t {
        sa_handler: nc::SIG_IGN,
        //sa_handler: handle_alarm as nc::sighandler_t,
        sa_flags: nc::SA_RESTART | nc::SA_SIGINFO | nc::SA_ONSTACK,
        ..nc::sigaction_t::default()
    };
    println!("sa size: {}", size_of_val(&sa));
    let mut old_sa = nc::sigaction_t::default();
    let ret = unsafe { nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>()) };
    assert!(ret.is_ok());

    let seconds = 1;
    let remaining = nc::util::alarm(seconds);

    let mask = nc::sigset_t::default();
    let ret = unsafe { nc::rt_sigsuspend(&mask, size_of::<nc::sigset_t>()) };
    assert!(ret.is_err());
    assert_eq!(ret, Err(nc::EINTR));

    assert_eq!(remaining.unwrap(), 0);
}

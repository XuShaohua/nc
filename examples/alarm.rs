// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use core::mem::{size_of, size_of_val};

fn handle_alarm(signum: i32) {
    println!("fuck alarm");
    assert_eq!(signum, nc::SIGALRM);
    //nc::exit(3);
}

fn main() {
    let sa = nc::sigaction_t {
        sa_sigaction: handle_alarm as nc::sighandler_t,
        sa_flags: nc::SA_RESTART | nc::SA_RESTORER,
        ..nc::sigaction_t::default()
    };
    println!("sa.sa_mask size: {}", size_of_val(&sa));
    let mut old_sa = nc::sigaction_t::default();
    let ret = nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>());
    assert!(ret.is_ok());
    let remaining = nc::alarm(1);
    let ret = nc::pause();
    assert!(ret.is_err());
    assert_eq!(ret, Err(nc::EINTR));
    assert_eq!(remaining, 0);
    println!("ret: {:?}", ret);
}

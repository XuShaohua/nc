// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use core::mem::size_of;

mod utils;

fn handle_restore() {
    //let msg = "Hello restore\n";
    //let _ = nc::write(2, msg.as_ptr() as usize, msg.len());
    // nc::rt_sigreturn();
    // do nothing.
}

fn handle_alarm(signum: i32) {
    assert_eq!(signum, nc::SIGALRM);
    //let msg = "Hello alarm\n";
    //let _ = nc::write(2, msg.as_ptr() as usize, msg.len());
    //nc::exit(1);
}

fn main() {
    let sa = nc::sigaction_t {
        sa_handler: handle_alarm as nc::sighandler_t,
        sa_flags: nc::SA_RESTORER,
        ..nc::sigaction_t::default()
    };
    let mut old_sa = nc::sigaction_t::default();
    let ret = nc::rt_sigaction(nc::SIGALRM, &sa, &mut old_sa, size_of::<nc::sigset_t>());
    assert!(ret.is_ok());

    // Single shot timer, active after 1 second.
    let itv = nc::itimerval_t {
        it_value: nc::timeval_t {
            tv_sec: 1,
            tv_usec: 0,
        },
        it_interval: nc::timeval_t {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    let mut prev_itv = nc::itimerval_t::default();
    let ret = nc::setitimer(nc::ITIMER_REAL, &itv, &mut prev_itv);
    assert!(ret.is_ok());

    let ret = nc::getitimer(nc::ITIMER_REAL, &mut prev_itv);
    assert!(ret.is_ok());
    assert!(prev_itv.it_value.tv_sec <= itv.it_value.tv_sec);

    let ret = utils::pause();
    assert_eq!(ret, Err(nc::EINTR));

    let ret = nc::getitimer(nc::ITIMER_REAL, &mut prev_itv);
    assert!(ret.is_ok());
    assert_eq!(prev_itv.it_value.tv_sec, 0);
    assert_eq!(prev_itv.it_value.tv_usec, 0);
    println!("prev_it: {:?}", prev_itv);
}

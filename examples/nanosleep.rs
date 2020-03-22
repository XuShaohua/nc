// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let req = nc::timespec_t {
        tv_sec: 3,
        tv_nsec: 0,
    };
    let mut rem = nc::timespec_t::default();
    println!("Sleep for 5 seconds...");
    let _ = nc::nanosleep(&req, &mut rem);
}

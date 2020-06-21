// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let mut t = nc::timespec_t::default();
    let ret = nc::clock_gettime(nc::CLOCK_REALTIME, &mut t);

    println!("ret is ok: {}", ret.is_ok());
    println!("sec: {}, usec: {}", t.tv_sec, t.tv_nsec);
}
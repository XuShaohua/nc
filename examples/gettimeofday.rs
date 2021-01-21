// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let mut timeval = nc::timeval_t::default();
    let mut timezone = nc::timezone_t::default();
    if let Err(errno) = nc::gettimeofday(&mut timeval, &mut timezone) {
        eprintln!("gettimeofday() failed: {}", nc::strerror(errno));
    } else {
        println!("time: {:+?}", timeval);
    }
}

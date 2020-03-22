// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let mut uts = nc::utsname_t::default();

    match nc::uname(&mut uts) {
        Ok(_) => {
            println!("utsname: {:?}", uts);
        }
        Err(errno) => {
            eprintln!("Failed to get uname: {}", errno);
        }
    }
}

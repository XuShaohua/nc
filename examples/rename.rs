// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let ret = nc::renameat(nc::AT_FDCWD, "hello.rs", nc::AT_FDCWD, "world.rs");
    match ret {
        Ok(_) => {
            println!("Rename file success!");
        }
        Err(errno) => {
            eprintln!("Failed to rename file, errno is: {}", errno);
        }
    }
}

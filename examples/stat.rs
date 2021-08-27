// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let mut statbuf = nc::stat_t::default();
    let filepath = "/dev/fd/0";

    let fd = nc::openat(nc::AT_FDCWD, filepath, nc::O_RDONLY, 0o644);
    assert!(fd.is_ok());
    let fd = fd.unwrap();
    let ret = nc::fstat(fd, &mut statbuf);
    assert!(nc::close(fd).is_ok());

    match ret {
        Ok(_) => {
            println!("s: {:?}", statbuf);
        }
        Err(errno) => {
            eprintln!(
                "Failed to get file status, got errno: {}",
                nc::strerror(errno)
            );
        }
    }
}

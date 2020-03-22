// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let fd = nc::openat(nc::AT_FDCWD, "/etc", nc::O_RDONLY | nc::O_DIRECTORY, 0)
        .expect("Failed to open folder");

    loop {
        match nc::getdents64(fd) {
            Ok(files) => {
                if files.is_empty() {
                    break;
                }

                for file in &files {
                    println!("file: {:?}", file);
                }
            }
            Err(err) => {
                eprintln!("err: {}", err);
                break;
            }
        }
    }

    let _ = nc::close(fd).expect("Failed to close fd");
}

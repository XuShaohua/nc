// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let msg = "hello, world\n";
    let nwrite = nc::write(-1, msg.as_ptr() as usize, msg.len());
    match nwrite {
        Ok(n) => {
            println!("nwrite: {}", n);
        }
        Err(errno) => {
            println!("errno: {}", errno);
            if errno == nc::EBADF {
                println!("Error: bad file descriptor");
            }
        }
    }

    let nwrite = nc::write(1, msg.as_ptr() as usize, msg.len());
    match nwrite {
        Ok(n) => {
            println!("nwrite: {}", n);
        }
        Err(errno) => {
            println!("errno: {}", errno);
        }
    }
}

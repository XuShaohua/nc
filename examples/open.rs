// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let path = "/tmp/hello.rs";

    #[cfg(target_os = "freebsd")]
    let fd = nc::open(
        path,
        nc::O_CREAT | nc::O_RDWR,
        nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
    )
    .map_err(|err| eprintln!("err: {}", err))
    .expect("Failed to open file!");

    #[cfg(target_os = "linux")]
    let fd = nc::openat(
        nc::AT_FDCWD,
        path,
        nc::O_CREAT | nc::O_RDWR,
        nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
    )
    .map_err(|err| eprintln!("err: {}", err))
    .expect("Failed to open file!");

    println!("fd: {:?}", fd);

    let msg = "fn main() { println!(\"Hello, world\");}";

    match nc::write(fd, msg.as_bytes()) {
        Ok(n) => {
            println!("Write {} chars", n);
        }
        Err(errno) => {
            eprintln!("Failed to write, got err: {}", errno);
        }
    }

    match nc::close(fd) {
        Ok(_) => {
            println!("File closed!");
        }
        Err(errno) => {
            eprintln!("Fail closed with errno: {}", errno);
        }
    }
}

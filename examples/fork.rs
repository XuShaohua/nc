// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

fn main() {
    let pid = nc::fork();
    match pid {
        Ok(pid) => {
            if pid == 0 {
                println!("parent process!");
            } else if pid < 0 {
                eprintln!("fork() error!");
            } else {
                println!("child process: {}", pid);
                let args = [""];
                let env = [""];
                match nc::execve("/bin/ls", &args, &env) {
                    Ok(_) => {}
                    Err(errno) => {
                        eprintln!("`ls` got err: {}", errno);
                    }
                }
            }
        }
        Err(errno) => {
            eprintln!("errno: {}", errno);
        }
    }
}

// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let mut statbuf = nc::stat_t::default();
    let filepath = "/dev/fd/0";
    #[cfg(not(any(target_arch = "aarch64", target_arch = "loongarch64")))]
    let ret = unsafe { nc::stat(filepath, &mut statbuf) };
    #[cfg(any(target_arch = "aarch64", target_arch = "loongarch64"))]
    let ret = unsafe { nc::fstatat(nc::AT_FDCWD, filepath, &mut statbuf, 0) };

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

// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let mut statbuf = nc::stat_t::default();
    let filepath = "/dev/fd/0";
    #[cfg(target_os = "linux")]
    let ret = {
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "loongarch64",
            target_arch = "riscv64"
        )))]
        unsafe {
            nc::stat(filepath, &mut statbuf)
        }

        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "loongarch64",
            target_arch = "riscv64"
        ))]
        unsafe {
            nc::fstatat(nc::AT_FDCWD, filepath, &mut statbuf, 0)
        }
    };
    #[cfg(all(any(
        all(target_os = "android", not(target_pointer_width = "32")),
        target_os = "freebsd"
    ),))]
    let ret = unsafe { nc::fstatat(nc::AT_FDCWD, filepath, &mut statbuf, 0) };

    #[cfg(all(any(target_os = "android"), target_pointer_width = "32"))]
    let mut stat64buf = nc::stat64_t::default();
    #[cfg(all(any(target_os = "android"), target_pointer_width = "32"))]
    let ret = unsafe { nc::fstatat64(nc::AT_FDCWD, filepath, &mut stat64buf, 0) };

    match ret {
        Ok(_) => {
            #[cfg(not(all(any(target_os = "android"), target_pointer_width = "32")))]
            println!("s: {:?}", statbuf);
            #[cfg(all(any(target_os = "android"), target_pointer_width = "32"))]
            println!("s: {:?}", stat64buf);
        }
        Err(errno) => {
            eprintln!(
                "Failed to get file status, got errno: {}",
                nc::strerror(errno)
            );
        }
    }
}

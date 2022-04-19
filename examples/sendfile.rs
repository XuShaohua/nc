// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    println!("S_IRUSR: {}", nc::S_IRUSR);
    println!("S_IRGRP: {}", nc::S_IRGRP);

    #[cfg(target_os = "linux")]
    let in_fd = unsafe {
        nc::openat(nc::AT_FDCWD, "/etc/passwd", nc::O_RDONLY, 0).expect("Failed to open file!")
    };

    #[cfg(target_os = "freebsd")]
    let in_fd = unsafe {
        nc::openat(nc::AT_FDCWD, "/etc/passwd", nc::O_RDONLY, 0).expect("Failed to open file!")
    };

    #[cfg(target_os = "linux")]
    let out_fd = unsafe {
        nc::openat(
            nc::AT_FDCWD,
            "/tmp/passwd.copy",
            nc::O_WRONLY | nc::O_CREAT,
            nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
        )
        .expect("Failed to open passwd copy file")
    };

    #[cfg(target_os = "freebsd")]
    let out_fd = unsafe {
        nc::openat(
            nc::AT_FDCWD,
            "/tmp/passwd.copy",
            nc::O_WRONLY | nc::O_CREAT,
            nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
        )
        .expect("Failed to open passwd copy file")
    };

    let mut stat = nc::stat_t::default();
    unsafe { nc::fstat(in_fd, &mut stat).expect("Failed to get file stat!") };
    println!("stat: {:?}", stat);

    let count = stat.st_blksize as usize;
    println!("count: {}", count);
    let mut offset = 0;
    let nread = unsafe {
        nc::sendfile(out_fd, in_fd, &mut offset, count).expect("Failed to call sendfile()")
    };
    println!("nbytes: {}", nread);

    unsafe {
        let _ = nc::close(in_fd);
        let _ = nc::close(out_fd);
    }
}

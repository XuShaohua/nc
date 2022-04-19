// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let path = std::path::Path::new("/tmp/nc.unlink");
    let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
    assert!(ret.is_ok());

    let path = std::path::PathBuf::from("/tmp/nc.unlink");
    let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
    assert!(ret.is_ok());

    let path = "/tmp/nc.unlink";
    let ret = unsafe { nc::unlinkat(nc::AT_FDCWD, path, 0) };
    assert!(ret.is_ok());
}

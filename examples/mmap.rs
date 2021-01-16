// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let path = "/etc/passwd";
    let ret = nc::open(path, nc::O_RDONLY, 0o644);
    assert!(ret.is_ok());
    let fd = ret.unwrap();

    let mut sb = nc::stat_t::default();
    let ret = nc::fstat(fd, &mut sb);
    assert!(ret.is_ok());

    let offset: usize = 0;
    let length: usize = sb.st_size as usize - offset;
    // Offset for mmap must be page aligned.
    let pa_offset: usize = offset & !(nc::PAGE_SIZE - 1);
    let map_length = length + offset - pa_offset;

    let addr = nc::mmap(
        0, // 0 as NULL
        map_length,
        nc::PROT_READ,
        nc::MAP_PRIVATE,
        fd,
        pa_offset as nc::off_t,
    );
    assert!(addr.is_ok());

    let addr = addr.unwrap();
    let n_write = nc::write(1, addr + offset - pa_offset, length);
    assert!(n_write.is_ok());
    assert_eq!(n_write, Ok(length as nc::ssize_t));
    assert!(nc::munmap(addr, map_length).is_ok());
    assert!(nc::close(fd).is_ok());
}

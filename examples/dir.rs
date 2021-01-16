// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn main() {
    let path = "/etc";
    let ret = nc::open(path, nc::O_DIRECTORY, 0);
    assert!(ret.is_ok());
    let fd = ret.unwrap();

    const BUF_SIZE: usize = 4 * 1024;
    loop {
        // TODO(Shaohua): Only allocate one buf block.
        let mut buf: Vec<u8> = vec![0; BUF_SIZE];
        let ret = nc::getdents64(fd, buf.as_mut_ptr() as usize, BUF_SIZE);
        assert!(ret.is_ok());

        let buf_box = buf.into_boxed_slice();
        let buf_box_ptr = Box::into_raw(buf_box) as *mut u8 as usize;
        let nread = ret.unwrap() as usize;
        if nread == 0 {
            break;
        }

        let mut bpos: usize = 0;
        while bpos < nread {
            let d = (buf_box_ptr + bpos) as *mut nc::linux_dirent64_t;
            let d_ref = unsafe { &(*d) };
            let mut name_vec: Vec<u8> = vec![];
            // TODO(Shaohua): Calculate string len of name.
            for i in 0..nc::PATH_MAX {
                let c = d_ref.d_name[i as usize];
                if c == 0 {
                    break;
                }
                name_vec.push(c);
            }
            let name = String::from_utf8(name_vec).unwrap();
            println!("name: {}", name);

            bpos += d_ref.d_reclen as usize;
        }
    }

    assert!(nc::close(fd).is_ok());
}

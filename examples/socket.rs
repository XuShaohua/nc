// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(unreachable_code)]

use core::mem::{size_of, transmute};
use nc::Errno;

fn htons(host: u16) -> u16 {
    host.to_be()
}

fn main() -> Result<(), Errno> {
    let listen_fd = unsafe { nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)? };

    let addr = nc::sockaddr_in_t {
        sin_family: nc::AF_INET as nc::sa_family_t,
        sin_port: htons(80),
        sin_addr: nc::in_addr_t {
            s_addr: nc::INADDR_ANY as u32,
        },
        ..Default::default()
    };

    unsafe {
        let addr_alias = transmute::<&nc::sockaddr_in_t, &nc::sockaddr_t>(&addr);
        let ret = nc::bind(listen_fd, addr_alias, size_of::<nc::sockaddr_in_t>() as u32);
        assert_eq!(ret, Err(nc::EACCES));
        return Ok(());

        nc::listen(listen_fd, nc::SOCK_STREAM)?;
    }

    let mut conn_addr = nc::sockaddr_in_t::default();
    let mut conn_addr_len: nc::socklen_t = 0;
    let conn_fd = unsafe {
        nc::accept4(
            listen_fd,
            &mut conn_addr,
            &mut conn_addr_len,
            nc::SOCK_CLOEXEC,
        )?
    };
    println!("conn_fd: {:?}", conn_fd);

    Ok(())
}

// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

extern crate nc;

use core::mem::size_of;
use nc::Errno;

fn test() -> Result<(), Errno> {
    let listen_fd = nc::socket(nc::AF_INET, nc::SOCK_STREAM, 0)?;

    let addr = nc::sockaddr_in_t {
        sin_family: nc::AF_INET as nc::sa_family_t,
        // TODO(Shaohua): Add htons()
        sin_port: 4200,
        sin_addr: nc::in_addr_t {
            s_addr: nc::INADDR_ANY as u32,
        },
        ..Default::default()
    };

    nc::bind(listen_fd, &addr, size_of::<nc::sockaddr_in_t>() as u32)?;

    nc::listen(listen_fd, nc::SOCK_STREAM)?;

    loop {
        let mut conn_addr = nc::sockaddr_in_t::default();
        let mut conn_addr_len: nc::socklen_t = 0;
        let conn_fd = nc::accept(listen_fd, &mut conn_addr, &mut conn_addr_len)?;
        println!("conn_fd: {:?}", conn_fd);
    }

    Ok(())
}

fn main() {
    match test() {
        Err(err) => eprintln!("err: {}", err),
        _ => {}
    }
}

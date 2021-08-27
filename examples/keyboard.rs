// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[allow(non_camel_case_types)]
extern crate nc;

use std::mem::size_of_val;

const UI_SET_EVBIT: i32 = 1074025828;
const UI_SET_KEYBIT: i32 = 1074025829;
const EV_SYN: usize = 0;
const EV_KEY: usize = 1;
const SYN_REPORT: usize = 0;
const KEY_M: usize = 50;
//const KEY_SPACE: usize = 57;
const UINPUT_MAX_NAME_SIZE: usize = 80;
const UI_DEV_SETUP: i32 = 1079792899;
const UI_DEV_CREATE: i32 = 21761;
const UI_DEV_DESTROY: i32 = 21762;
const BUS_USB: u16 = 3;

/// Input event struct.
/// Defined in linux/uinput.h
#[repr(C)]
pub struct input_event_t {
    pub time: nc::timeval_t,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct input_id_t {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

#[repr(C)]
pub struct uinput_setup_t {
    pub id: input_id_t,
    pub name: [u8; UINPUT_MAX_NAME_SIZE],
    pub ff_effects_max: u32,
}

fn sleep(n: isize) {
    let req = nc::timespec_t {
        tv_sec: n,
        tv_nsec: 0,
    };
    let _ = nc::nanosleep(&req, None);
}

fn emit(fd: i32, event_type: u16, code: u16, value: i32) -> Result<isize, nc::Errno> {
    let ie = input_event_t {
        type_: event_type,
        code: code,
        value: value,
        time: nc::timeval_t {
            tv_sec: 0,
            tv_usec: 0,
        },
    };

    nc::write(fd, &ie as *const input_event_t as usize, size_of_val(&ie))
}

fn run() -> Result<(), nc::Errno> {
    let fd = {
        match nc::openat(
            nc::AT_FDCWD,
            "/dev/uinput",
            nc::O_WRONLY | nc::O_NONBLOCK,
            0,
        ) {
            Ok(fd) => fd,
            Err(errno) => {
                println!("Error to open uinput: {}", errno);
                return Err(errno);
            }
        }
    };

    nc::ioctl(fd, UI_SET_EVBIT, EV_KEY)?;
    nc::ioctl(fd, UI_SET_KEYBIT, KEY_M)?;

    let mut usetup = uinput_setup_t {
        id: input_id_t {
            bustype: BUS_USB,
            vendor: 0x1234,
            product: 0x5678,
            version: 0,
        },
        name: [0; UINPUT_MAX_NAME_SIZE],
        ff_effects_max: 0,
    };
    usetup.name[0] = 69;
    usetup.name[1] = 120;
    usetup.name[2] = 97;

    nc::ioctl(fd, UI_DEV_SETUP, &usetup as *const uinput_setup_t as usize)
        .expect("UI_DEV_SETUP failed");
    nc::ioctl(fd, UI_DEV_CREATE, 0).expect("UI_DEV_CREATE");

    sleep(1);

    emit(fd, EV_KEY as u16, KEY_M as u16, 1).expect("KEY space");
    emit(fd, EV_SYN as u16, SYN_REPORT as u16, 0).expect("sync report");
    emit(fd, EV_KEY as u16, KEY_M as u16, 0).expect("key space 0");
    emit(fd, EV_SYN as u16, SYN_REPORT as u16, 0).expect("sync report 0");

    sleep(1);

    nc::ioctl(fd, UI_DEV_DESTROY, 0).expect("DEV_DESTROY");
    nc::close(fd).expect("close()");

    return Ok(());
}

fn main() {
    if let Err(errno) = run() {
        panic!("errno: {}", errno);
    }
}

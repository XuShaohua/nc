// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

// Length of the entries in `struct utsname_t` is 65.
const UTSNAME_LENGTH: usize = 65;

#[repr(C)]
#[derive(Clone)]
pub struct new_utsname_t {
    pub sysname: [u8; UTSNAME_LENGTH],
    pub nodename: [u8; UTSNAME_LENGTH],
    pub release: [u8; UTSNAME_LENGTH],
    pub version: [u8; UTSNAME_LENGTH],
    pub machine: [u8; UTSNAME_LENGTH],
    pub domainname: [u8; UTSNAME_LENGTH],
}

pub type utsname_t = new_utsname_t;

impl core::fmt::Debug for utsname_t {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        unsafe {
            write!(
                f,
                "utsname_t {{ sysname: {}, nodename: {}, release: {}, \
                 version: {}, machine: {}, domainname: {} }}",
                core::str::from_utf8_unchecked(&self.sysname),
                core::str::from_utf8_unchecked(&self.nodename),
                core::str::from_utf8_unchecked(&self.release),
                core::str::from_utf8_unchecked(&self.version),
                core::str::from_utf8_unchecked(&self.machine),
                core::str::from_utf8_unchecked(&self.domainname)
            )
        }
    }
}

impl Default for utsname_t {
    fn default() -> Self {
        utsname_t {
            sysname: [0; UTSNAME_LENGTH],
            nodename: [0; UTSNAME_LENGTH],
            release: [0; UTSNAME_LENGTH],
            version: [0; UTSNAME_LENGTH],
            machine: [0; UTSNAME_LENGTH],
            domainname: [0; UTSNAME_LENGTH],
        }
    }
}

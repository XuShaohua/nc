const OLD_UTS_LEN: usize = 8;

#[repr(C)]
pub struct oldold_utsname_t {
    pub sysname: [u8; 9],
    pub nodename: [u8; 9],
    pub release: [u8; 9],
    pub version: [u8; 9],
    pub machine: [u8; 9],
}

const NEW_UTS_LEN: usize = 64;

#[repr(C)]
pub struct old_utsname_t {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
}

#[repr(C)]
pub struct new_utsname_t {
    pub sysname: [u8; NEW_UTS_LEN + 1],
    pub nodename: [u8; NEW_UTS_LEN + 1],
    pub release: [u8; NEW_UTS_LEN + 1],
    pub version: [u8; NEW_UTS_LEN + 1],
    pub machine: [u8; NEW_UTS_LEN + 1],
    pub domainname: [u8; NEW_UTS_LEN + 1],
}

pub type utsname_t = new_utsname_t;

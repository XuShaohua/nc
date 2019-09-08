use super::types::*;

/// From fs/readir.c

#[repr(C)]
pub struct linux_dirent_t {
    pub d_ino: ino_t,
    pub d_off: off_t,
    pub d_reclen: u16,
    pub d_name: [u8; 1],
}

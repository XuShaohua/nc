use super::types::*;

#[repr(C)]
pub struct linux_dirent64_t {
    pub d_ino: ino_t,
    pub d_off: off_t,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 0],
}

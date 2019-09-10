use super::limits::*;
use super::types::*;
use alloc::string::String;

#[repr(C)]
#[derive(Clone)]
pub struct linux_dirent64_t {
    /// 64-bit inode number.
    pub d_ino: ino64_t,

    /// 64-bit offset to next structure.
    pub d_off: loff_t,

    /// Size of this dirent.
    pub d_reclen: u16,

    /// File type.
    pub d_type: u8,

    /// Filename (null-terminated).
    //pub d_name: [u8; 0],
    pub d_name: [u8; PATH_MAX as usize],
}

#[derive(Clone, Debug)]
pub struct linux_dirent64_extern_t {
    /// 64-bit inode number.
    pub d_ino: ino64_t,

    /// 64-bit offset to next structure.
    pub d_off: loff_t,

    /// File type.
    pub d_type: u8,

    /// Filename.
    pub d_name: String,
}

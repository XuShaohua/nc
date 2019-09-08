use super::types::*;

#[repr(C)]
pub struct linux_dirent64_t {
    /// 64-bit inode number.
    pub d_ino: ino64_t,

    /// 64-bit offset to next structure.
    pub d_off: loff_t,

    /// Size of this dirent.
    pub d_reclen: u16,

    /// File type.
    pub d_type: u8,

    /// Filename (null-terminated.
    pub d_name: [u8; 0],
}

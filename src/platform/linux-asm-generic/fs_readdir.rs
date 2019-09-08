use super::types::*;

/// From fs/readir.c

#[repr(C)]
pub struct linux_dirent_t {
    /// Inode number
    pub d_ino: ino_t,

    /// Offset to next linux_dirent
    pub d_off: off_t,

    /// Length of this linux_dirent
    pub d_reclen: u16,

    /// Filename (null-terminated)
    pub d_name: [u8; 1],
}

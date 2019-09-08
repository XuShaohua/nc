use super::types::*;

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;

#[repr(C)]
#[derive(Clone, Debug)]
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
    //pub d_name: [u8; 0],
    pub d_name: [u8; 1],
}

pub fn get_linux_dirent64_name(ptr: usize) -> String {
    unsafe {
        let d = ptr as *mut linux_dirent64_t;
        let mut name_start =
            ptr + size_of::<ino64_t>() + size_of::<loff_t>() + size_of::<u16>() + size_of::<u8>();

        let name_end = ptr + (*d).d_reclen as usize;
        let name_len = name_end - name_start;
        let mut name_vec: Vec<u8> = Vec::with_capacity(name_len);
        while name_start < name_end {
            let c = (ptr + name_start) as *mut u8;
            name_vec.push(c as u8);
            name_start += 1;
        }

        String::from_utf8(name_vec).unwrap()
    }
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

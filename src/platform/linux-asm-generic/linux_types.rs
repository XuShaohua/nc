use super::types::*;

pub type dev_t = u32;
pub type nlink_t = u32;
pub type umode_t = u16;

/// The type used for indexing onto a disc or disc partition.
///
/// Linux always considers sectors to be 512 bytes long independently
/// of the devices real block size.
///
/// blkcnt_t is the type of the inode's block count.
//TODO(Shaohua): #ifdef CONFIG_LBDAF
pub type sector_t = usize;
pub type blkcnt_t = usize;

/// The type of an index into the pagecache.
pub type pgoff_t = usize;

pub type gfp_t = u32;
pub type slab_flags_t = u32;
pub type fmode_t = u32;

#[repr(C)]
pub struct ustat_t {
    pub f_tfree: usize,
    pub f_tinode: ino_t,
    pub f_fname: [u8; 6],
    pub f_fpack: [u8; 6],
}

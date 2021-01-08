// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// This file has definitions for some important file table structures
/// and constants and structures used by various generic file system
/// ioctl's.  Please do not make any changes in this file before
/// sending patches for review to linux-fsdevel@vger.kernel.org and
/// linux-api@vger.kernel.org.

/// Use of MS_* flags within the kernel is restricted to core mount(2) code.

/// It's silly to have NR_OPEN bigger than NR_FILE, but you can change
/// the file limit at runtime and only root can increase the per-process
/// nr_file rlimit, so it's safe to set up a ridiculously high absolute
/// upper limit on files-per-process.
///
/// Some programs (notably those using select()) may have to be
/// ecompiled to take full advantage of the new limits..  

/// Fixed constants first:
/// Initial setting for nfile rlimits
pub const INR_OPEN_CUR: i32 = 1024;
/// Hard limit for nfile rlimits
pub const INR_OPEN_MAX: i32 = 4096;

pub const BLOCK_SIZE_BITS: i32 = 10;
pub const BLOCK_SIZE: i32 = 1 << BLOCK_SIZE_BITS;

/// seek relative to beginning of file
pub const SEEK_SET: i32 = 0;
/// seek relative to current file position
pub const SEEK_CUR: i32 = 1;
/// seek relative to end of file
pub const SEEK_END: i32 = 2;
/// seek to the next data
pub const SEEK_DATA: i32 = 3;
/// seek to the next hole
pub const SEEK_HOLE: i32 = 4;
pub const SEEK_MAX: i32 = SEEK_HOLE;

/// Don't overwrite target
pub const RENAME_NOREPLACE: i32 = 1;
/// Exchange source and dest
pub const RENAME_EXCHANGE: i32 = 1 << 1;
/// Whiteout source
pub const RENAME_WHITEOUT: i32 = 1 << 2;

#[repr(C)]
#[derive(Debug, Default)]
pub struct file_clone_range_t {
    pub src_fd: i64,
    pub src_offset: u64,
    pub src_length: u64,
    pub dest_offset: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fstrim_range_t {
    pub start: u64,
    pub len: u64,
    pub minlen: u64,
}

/// extent-same (dedupe) ioctls; these MUST match the btrfs ioctl definitions
pub const FILE_DEDUPE_RANGE_SAME: i32 = 0;
pub const FILE_DEDUPE_RANGE_DIFFERS: i32 = 1;

/// from struct btrfs_ioctl_file_extent_same_info
#[repr(C)]
#[derive(Debug, Default)]
pub struct file_dedupe_range_info_t {
    /// in - destination file
    pub dest_fd: i64,
    /// in - start of extent in destination
    pub dest_offset: u64,
    /// out - total # of bytes we were able to dedupe from this file.
    pub bytes_deduped: u64,
    /// status of this dedupe operation:
    /// < 0 for error
    /// == FILE_DEDUPE_RANGE_SAME if dedupe succeeds
    /// == FILE_DEDUPE_RANGE_DIFFERS if data differs
    /// out - see above description
    pub status: i32,
    /// must be zero
    pub reserved: u32,
}

/// from struct btrfs_ioctl_file_extent_same_args
#[repr(C)]
#[derive(Debug)]
pub struct file_dedupe_range_t {
    /// in - start of extent in source
    pub src_offset: u64,
    /// in - length of extent
    pub src_length: u64,
    /// in - total elements in info array
    pub dest_count: u16,
    /// must be zero
    pub reserved1: u16,
    /// must be zero
    pub reserved2: u32,
    pub info: *mut file_dedupe_range_info_t,
}

/// And dynamically-tunable limits and defaults:
#[repr(C)]
#[derive(Debug, Default)]
pub struct files_stat_struct_t {
    /// read only
    pub nr_files: usize,
    /// read only
    pub nr_free_files: usize,
    /// tunable
    pub max_files: usize,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct inodes_stat_t {
    pub nr_inodes: isize,
    pub nr_unused: isize,
    /// padding for sysctl ABI compatibility
    dummy: [isize; 5],
}

pub const NR_FILE: i32 = 8192; /* this can well be larger on a larger system */

/// Structure for FS_IOC_FSGETXATTR[A] and FS_IOC_FSSETXATTR.
#[repr(C)]
#[derive(Debug, Default)]
pub struct fsxattr_t {
    /// xflags field value (get/set)
    pub fsx_xflags: u32,
    /// extsize field value (get/set)
    pub fsx_extsize: u32,
    /// nextents field value (get)
    pub fsx_nextents: u32,
    /// project identifier (get/set)
    pub fsx_projid: u32,
    /// CoW extsize field value (get/set)
    pub fsx_cowextsize: u32,
    fsx_pad: [u8; 8],
}

/// Flags for the fsx_xflags field
/// data in realtime volume
pub const FS_XFLAG_REALTIME: i32 = 0x0000_0001;
/// preallocated file extents
pub const FS_XFLAG_PREALLOC: i32 = 0x0000_0002;
/// file cannot be modified
pub const FS_XFLAG_IMMUTABLE: i32 = 0x0000_0008;
/// all writes append
pub const FS_XFLAG_APPEND: i32 = 0x0000_0010;
/// all writes synchronous
pub const FS_XFLAG_SYNC: i32 = 0x0000_0020;
/// do not update access time
pub const FS_XFLAG_NOATIME: i32 = 0x0000_0040;
/// do not include in backups
pub const FS_XFLAG_NODUMP: i32 = 0x0000_0080;
/// create with rt bit set
pub const FS_XFLAG_RTINHERIT: i32 = 0x0000_0100;
/// create with parents projid
pub const FS_XFLAG_PROJINHERIT: i32 = 0x0000_0200;
/// disallow symlink creation
pub const FS_XFLAG_NOSYMLINKS: i32 = 0x0000_0400;
/// extent size allocator hint
pub const FS_XFLAG_EXTSIZE: i32 = 0x0000_0800;
/// inherit inode extent size
pub const FS_XFLAG_EXTSZINHERIT: i32 = 0x0000_1000;
/// do not defragment
pub const FS_XFLAG_NODEFRAG: i32 = 0x0000_2000;
/// use filestream allocator
pub const FS_XFLAG_FILESTREAM: i32 = 0x0000_4000;
/// use DAX for IO
pub const FS_XFLAG_DAX: i32 = 0x0000_8000;
/// CoW extent size allocator hint
pub const FS_XFLAG_COWEXTSIZE: i32 = 0x0001_0000;
/// no DIFLAG for this
#[allow(overflowing_literals)]
pub const FS_XFLAG_HASATTR: i32 = 0x8000_0000;

/// the read-only stuff doesn't really belong here, but any other place is
/// probably as bad and I don't want to create yet another include file.
//pub const BLKROSET: i32 = _IO!(0x12,93)	/* set device read-only (0 = read-write) */
//pub const BLKROGET: i32 = _IO!(0x12,94)	/* get read-only status (0 = read_write) */
//pub const BLKRRPART: i32 = _IO!(0x12,95)	/* re-read partition table */
//pub const BLKGETSIZE: i32 = _IO!(0x12,96)	/* return device size /512 (long *arg) */
//pub const BLKFLSBUF: i32 = _IO!(0x12,97)	/* flush buffer cache */
//pub const BLKRASET: i32 = _IO!(0x12,98)	/* set read ahead for block device */
//pub const BLKRAGET: i32 = _IO!(0x12,99)	/* get current read ahead setting */
//pub const BLKFRASET: i32 = _IO!(0x12,100)/* set filesystem (mm/filemap.c) read-ahead */
//pub const BLKFRAGET: i32 = _IO!(0x12,101)/* get filesystem (mm/filemap.c) read-ahead */
//pub const BLKSECTSET: i32 = _IO!(0x12,102)/* set max sectors per request (ll_rw_blk.c) */
//pub const BLKSECTGET: i32 = _IO!(0x12,103)/* get max sectors per request (ll_rw_blk.c) */
//pub const BLKSSZGET: i32 = _IO!(0x12,104)/* get block device sector size */

// A jump here: 108-111 have been used for various private purposes.

//pub const BLKBSZGET: i32 = _IOR!(0x12,112,size_t)
//pub const BLKBSZSET: i32 = _IOW!(0x12,113,size_t)
//pub const BLKGETSIZE64: i32 = _IOR!(0x12,114,size_t)	/* return device size in bytes (u64 *arg) */
//pub const BLKTRACESETUP: i32 = _IOWR!(0x12,115,struct blk_user_trace_setup)
//pub const BLKTRACESTART: i32 = _IO!(0x12,116)
//pub const BLKTRACESTOP: i32 = _IO!(0x12,117)
//pub const BLKTRACETEARDOWN: i32 = _IO!(0x12,118)
//pub const BLKDISCARD: i32 = _IO!(0x12,119)
//pub const BLKIOMIN: i32 = _IO!(0x12,120)
//pub const BLKIOOPT: i32 = _IO!(0x12,121)
//pub const BLKALIGNOFF: i32 = _IO!(0x12,122)
//pub const BLKPBSZGET: i32 = _IO!(0x12,123)
//pub const BLKDISCARDZEROES: i32 = _IO!(0x12,124)
//pub const BLKSECDISCARD: i32 = _IO!(0x12,125)
//pub const BLKROTATIONAL: i32 = _IO!(0x12,126)
//pub const BLKZEROOUT: i32 = _IO!(0x12,127)

// A jump here: 130-131 are reserved for zoned block devices
// (see uapi/linux/blkzoned.h)

//pub const BMAP_IOCTL: i32 = 1;		/* obsolete - kept for compatibility */
//pub const FIBMAP: i32 = _IO!(0x00,1)	/* bmap access */
//pub const FIGETBSZ: i32 = _IO!(0x00,2)	/* get the block size used for bmap */
//pub const FIFREEZE: i32 = _IOWR!('X', 119, int)	/* Freeze */
//pub const FITHAW: i32 = _IOWR!('X', 120, int)	/* Thaw */
//pub const FITRIM: i32 = _IOWR!('X', 121, struct fstrim_range)	/* Trim */
//pub const FICLONE: i32 = _IOW!(0x94, 9, int)
//pub const FICLONERANGE: i32 = _IOW!(0x94, 13, struct file_clone_range)
//pub const FIDEDUPERANGE: i32 = _IOWR!(0x94, 54, struct file_dedupe_range)

/// Max chars for the interface; each fs may differ
pub const FSLABEL_MAX: i32 = 256;

//pub const FS_IOC_GETFLAGS: i32 = _IOR!('f', 1, long)
//pub const FS_IOC_SETFLAGS: i32 = _IOW!('f', 2, long)
//pub const FS_IOC_GETVERSION: i32 = _IOR!('v', 1, long)
//pub const FS_IOC_SETVERSION: i32 = _IOW!('v', 2, long)
//pub const FS_IOC_FIEMAP: i32 = _IOWR!('f', 11, struct fiemap)
//pub const FS_IOC32_GETFLAGS: i32 = _IOR!('f', 1, int)
//pub const FS_IOC32_SETFLAGS: i32 = _IOW!('f', 2, int)
//pub const FS_IOC32_GETVERSION: i32 = _IOR!('v', 1, int)
//pub const FS_IOC32_SETVERSION: i32 = _IOW!('v', 2, int)
//pub const FS_IOC_FSGETXATTR: i32 = _IOR!('X', 31, struct fsxattr)
//pub const FS_IOC_FSSETXATTR: i32 = _IOW!('X', 32, struct fsxattr)
//pub const FS_IOC_GETFSLABEL: i32 = _IOR!(0x94, 49, char[FSLABEL_MAX])
//pub const FS_IOC_SETFSLABEL: i32 = _IOW!(0x94, 50, char[FSLABEL_MAX])

/// File system encryption support
/// Policy provided via an ioctl on the topmost directory
pub const FS_KEY_DESCRIPTOR_SIZE: i32 = 8;

pub const FS_POLICY_FLAGS_PAD_4: i32 = 0x00;
pub const FS_POLICY_FLAGS_PAD_8: i32 = 0x01;
pub const FS_POLICY_FLAGS_PAD_16: i32 = 0x02;
pub const FS_POLICY_FLAGS_PAD_32: i32 = 0x03;
pub const FS_POLICY_FLAGS_PAD_MASK: i32 = 0x03;
/// use master key directly
pub const FS_POLICY_FLAGS_VALID: i32 = 0x07;

/// Encryption algorithms
pub const FS_ENCRYPTION_MODE_INVALID: i32 = 0;
pub const FS_ENCRYPTION_MODE_AES_256_XTS: i32 = 1;
pub const FS_ENCRYPTION_MODE_AES_256_GCM: i32 = 2;
pub const FS_ENCRYPTION_MODE_AES_256_CBC: i32 = 3;
pub const FS_ENCRYPTION_MODE_AES_256_CTS: i32 = 4;
pub const FS_ENCRYPTION_MODE_AES_128_CBC: i32 = 5;
pub const FS_ENCRYPTION_MODE_AES_128_CTS: i32 = 6;
/// Removed, do not use.
pub const FS_ENCRYPTION_MODE_SPECK128_256_XTS: i32 = 7;
/// Removed, do not use.
pub const FS_ENCRYPTION_MODE_SPECK128_256_CTS: i32 = 8;
pub const FS_ENCRYPTION_MODE_ADIANTUM: i32 = 9;

#[repr(C)]
#[derive(Debug, Default)]
pub struct fscrypt_policy_t {
    pub version: u8,
    pub contents_encryption_mode: u8,
    pub filenames_encryption_mode: u8,
    pub flags: u8,
    pub master_key_descriptor: [u8; FS_KEY_DESCRIPTOR_SIZE as usize],
}

// TODO(Shaohua):
//pub const FS_IOC_SET_ENCRYPTION_POLICY: i32 = _IOR;('f', 19, struct fscrypt_policy)
//pub const FS_IOC_GET_ENCRYPTION_PWSALT: i32 = _IOW;('f', 20, __u8[16])
//pub const FS_IOC_GET_ENCRYPTION_POLICY: i32 = _IOW;('f', 21, struct fscrypt_policy)

/// Parameters for passing an encryption key into the kernel keyring
pub const FS_KEY_DESC_PREFIX: &str = "fscrypt:";
pub const FS_KEY_DESC_PREFIX_SIZE: i32 = 8;

/// Structure that userspace passes to the kernel keyring
pub const FS_MAX_KEY_SIZE: i32 = 64;

#[repr(C)]
#[derive(Debug)]
pub struct fscrypt_key_t {
    pub mode: u32,
    pub raw: [u8; FS_MAX_KEY_SIZE as usize],
    pub size: u32,
}

/// Inode flags (FS_IOC_GETFLAGS / FS_IOC_SETFLAGS)
///
/// Note: for historical reasons, these flags were originally used and
/// defined for use by ext2/ext3, and then other file systems started
/// using these flags so they wouldn't need to write their own version
/// of chattr/lsattr (which was shipped as part of e2fsprogs).  You
/// should think twice before trying to use these flags in new
/// contexts, or trying to assign these flags, since they are used both
/// as the UAPI and the on-disk encoding for ext2/3/4.  Also, we are
/// almost out of 32-bit flags.  :-)
///
/// We have recently hoisted FS_IOC_FSGETXATTR / FS_IOC_FSSETXATTR from
/// XFS to the generic FS level interface.  This uses a structure that
/// has padding and hence has more room to grow, so it may be more
/// appropriate for many new use cases.
///
/// Please do not change these flags or interfaces before checking with
/// linux-fsdevel@vger.kernel.org and linux-api@vger.kernel.org.
/// Secure deletion
pub const FS_SECRM_FL: i32 = 0x0000_0001;
/// Undelete
pub const FS_UNRM_FL: i32 = 0x0000_0002;
/// Compress file
pub const FS_COMPR_FL: i32 = 0x0000_0004;
/// Synchronous updates
pub const FS_SYNC_FL: i32 = 0x0000_0008;
/// Immutable file
pub const FS_IMMUTABLE_FL: i32 = 0x0000_0010;
/// writes to file may only append
pub const FS_APPEND_FL: i32 = 0x0000_0020;
/// do not dump file
pub const FS_NODUMP_FL: i32 = 0x0000_0040;
/// do not update atime
pub const FS_NOATIME_FL: i32 = 0x0000_0080;
/// Reserved for compression usage...
pub const FS_DIRTY_FL: i32 = 0x0000_0100;
/// One or more compressed clusters
pub const FS_COMPRBLK_FL: i32 = 0x0000_0200;
/// Don't compress
pub const FS_NOCOMP_FL: i32 = 0x0000_0400;
/// End compression flags --- maybe not all used
/// Encrypted file
pub const FS_ENCRYPT_FL: i32 = 0x0000_0800;
/// btree format dir
pub const FS_BTREE_FL: i32 = 0x0000_1000;
/// hash-indexed directory
pub const FS_INDEX_FL: i32 = 0x0000_1000;
/// AFS directory
pub const FS_IMAGIC_FL: i32 = 0x0000_2000;
/// Reserved for ext3
pub const FS_JOURNAL_DATA_FL: i32 = 0x0000_4000;
/// file tail should not be merged
pub const FS_NOTAIL_FL: i32 = 0x0000_8000;
/// dirsync behaviour (directories only)
pub const FS_DIRSYNC_FL: i32 = 0x0001_0000;
/// Top of directory hierarchies
pub const FS_TOPDIR_FL: i32 = 0x0002_0000;
/// Reserved for ext4
pub const FS_HUGE_FILE_FL: i32 = 0x0004_0000;
/// Extents
pub const FS_EXTENT_FL: i32 = 0x0008_0000;
/// Inode used for large EA
pub const FS_EA_INODE_FL: i32 = 0x0020_0000;
/// Reserved for ext4
pub const FS_EOFBLOCKS_FL: i32 = 0x0040_0000;
/// Do not cow file
pub const FS_NOCOW_FL: i32 = 0x0080_0000;
/// Reserved for ext4
pub const FS_INLINE_DATA_FL: i32 = 0x1000_0000;
/// Create with parents projid
pub const FS_PROJINHERIT_FL: i32 = 0x2000_0000;
/// reserved for ext2 lib
#[allow(overflowing_literals)]
pub const FS_RESERVED_FL: i32 = 0x8000_0000;

/// User visible flags
pub const FS_FL_USER_VISIBLE: i32 = 0x0003_DFFF;
/// User modifiable flags
pub const FS_FL_USER_MODIFIABLE: i32 = 0x0003_80FF;

pub const SYNC_FILE_RANGE_WAIT_BEFORE: i32 = 1;
pub const SYNC_FILE_RANGE_WRITE: i32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: i32 = 4;

/// Flags for preadv2/pwritev2:
pub type rwf_t = i32;

/// high priority request, poll if possible
pub const RWF_HIPRI: rwf_t = 0x0000_0001;

/// per-IO O_DSYNC
pub const RWF_DSYNC: rwf_t = 0x0000_0002;

/// per-IO O_SYNC
pub const RWF_SYNC: rwf_t = 0x0000_0004;

/// per-IO, return -EAGAIN if operation would block
pub const RWF_NOWAIT: rwf_t = 0x0000_0008;

/// per-IO O_APPEND
pub const RWF_APPEND: rwf_t = 0x0000_0010;

/// mask of flags supported by the kernel
pub const RWF_SUPPORTED: rwf_t = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;

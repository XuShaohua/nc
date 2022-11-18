// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `include/uapi/linux/mount.h`

/// These are the fs-independent mount-flags: up to 32 flags are supported
///
/// Usage of these is restricted within the kernel to core mount(2) code and
/// callers of `sys_mount()` only.  Filesystems should be using the `SB_*`
/// equivalent instead.
///
/// Mount read-only
pub const MS_RDONLY: usize = 1;
/// Ignore suid and sgid bits
pub const MS_NOSUID: usize = 2;
/// Disallow access to device special files
pub const MS_NODEV: usize = 4;
/// Disallow program execution
pub const MS_NOEXEC: usize = 8;
/// Writes are synced at once
pub const MS_SYNCHRONOUS: usize = 16;
/// Alter flags of a mounted FS
pub const MS_REMOUNT: usize = 32;
/// Allow mandatory locks on an FS
pub const MS_MANDLOCK: usize = 64;
/// Directory modifications are synchronous
pub const MS_DIRSYNC: usize = 128;
/// Do not update access times.
pub const MS_NOATIME: usize = 1024;
/// Do not update directory access times
pub const MS_NODIRATIME: usize = 2048;
pub const MS_BIND: usize = 4096;
pub const MS_MOVE: usize = 8192;
pub const MS_REC: usize = 16384;
/// `MS_VERBOSE` is deprecated.
pub const MS_VERBOSE: usize = 32768;
pub const MS_SILENT: usize = 32768;
/// VFS does not apply the umask
pub const MS_POSIXACL: usize = 1 << 16;
/// change to unbindable
pub const MS_UNBINDABLE: usize = 1 << 17;
/// change to private
pub const MS_PRIVATE: usize = 1 << 18;
/// change to slave
pub const MS_SLAVE: usize = 1 << 19;
/// change to shared
pub const MS_SHARED: usize = 1 << 20;
/// Update atime relative to mtime/ctime.
pub const MS_RELATIME: usize = 1 << 21;
/// this is a `kern_mount` call
pub const MS_KERNMOUNT: usize = 1 << 22;
/// Update inode `I_version` field
pub const MS_I_VERSION: usize = 1 << 23;
/// Always perform atime updates
pub const MS_STRICTATIME: usize = 1 << 24;
/// Update the on-disk `acm` times lazily
pub const MS_LAZYTIME: usize = 1 << 25;

/// These sb flags are internal to the kernel
pub const MS_SUBMOUNT: usize = 1 << 26;
pub const MS_NOREMOTELOCK: usize = 1 << 27;
pub const MS_NOSEC: usize = 1 << 28;
pub const MS_BORN: usize = 1 << 29;
pub const MS_ACTIVE: usize = 1 << 30;
pub const MS_NOUSER: usize = 1 << 31;

///  Superblock flags that can be altered by `MS_REMOUNT`
pub const MS_RMT_MASK: usize =
    MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME;

/// Old magic mount flag and mask
pub const MS_MGC_VAL: usize = 0xC0ED_0000;
pub const MS_MGC_MSK: usize = 0xffff_0000;

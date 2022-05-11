// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// From `arch/x86/include/asm/compat.h`
use crate::{
    __kernel_fsid_t, compat_ino_t, compat_key_t, compat_loff_t, compat_off_t, compat_pid_t,
    compat_size_t, compat_ulong_t,
};

pub const COMPAT_USER_HZ: i32 = 100;
pub const COMPAT_UTS_MACHINE: &str = "i686\0\0";

pub type __compat_uid_t = u16;

pub type __compat_gid_t = u16;
pub type __compat_uid32_t = u32;
pub type __compat_gid32_t = u32;
pub type compat_mode_t = u16;
pub type compat_dev_t = u16;
pub type compat_nlink_t = u16;
pub type compat_ipc_pid_t = u16;
pub type compat_caddr_t = u32;
pub type compat_fsid_t = __kernel_fsid_t;

#[repr(C)]
#[derive(Debug)]
pub struct compat_stat_t {
    pub st_dev: compat_dev_t,
    pub __pad1: u16,
    pub st_ino: compat_ino_t,
    pub st_mode: compat_mode_t,
    pub st_nlink: compat_nlink_t,
    pub st_uid: __compat_uid_t,
    pub st_gid: __compat_gid_t,
    pub st_rdev: compat_dev_t,
    pub __pad2: u16,
    pub st_size: u32,
    pub st_blksize: u32,
    pub st_blocks: u32,
    pub st_atime: u32,
    pub st_atime_nsec: u32,
    pub st_mtime: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime: u32,
    pub st_ctime_nsec: u32,
    pub __unused4: u32,
    pub __unused5: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct compat_flock_t {
    pub l_type: u16,
    pub l_whence: u16,
    pub l_start: compat_off_t,
    pub l_len: compat_off_t,
    pub l_pid: compat_pid_t,
}

/// using 'struct flock64'
pub const F_GETLK64: i32 = 12;
pub const F_SETLK64: i32 = 13;
pub const F_SETLKW64: i32 = 14;

/// IA32 uses 4 byte alignment for 64 bit quantities,
/// so we need to pack this structure.
#[repr(C)]
#[derive(Debug)]
pub struct compat_flock64_t {
    pub l_type: u16,
    pub l_whence: u16,
    pub l_start: compat_loff_t,
    pub l_len: compat_loff_t,
    pub l_pid: compat_pid_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct compat_statfs_t {
    pub f_type: i32,
    pub f_bsize: i32,
    pub f_blocks: i32,
    pub f_bfree: i32,
    pub f_bavail: i32,
    pub f_files: i32,
    pub f_free: i32,
    pub f_fsid: compat_fsid_t,

    /// SunOS ignores this field.
    pub f_namelen: i32,
    pub f_frsize: i32,
    pub f_flags: i32,
    pub f_spare: [i32; 4],
}

pub const COMPAT_RLIM_INFINITY: u32 = 0xffff_ffff;

/// at least 32 bits
pub type compat_old_sigset_t = u32;

pub const _COMPAT_NSIG: i32 = 64;
pub const _COMPAT_NSIG_BPW: i32 = 32;

pub type compat_sigset_word = u32;

pub const COMPAT_OFF_T_MAX: u32 = 0x7fff_ffff;

#[repr(C)]
#[derive(Debug)]
pub struct compat_ipc64_perm_t {
    pub key: compat_key_t,
    pub uid: __compat_uid32_t,
    pub gid: __compat_gid32_t,
    pub cuid: __compat_uid32_t,
    pub cgid: __compat_gid32_t,
    pub mode: u16,
    __pad1: u16,
    pub seq: u16,
    __pad2: u16,
    pub unused1: compat_ulong_t,
    pub unused2: compat_ulong_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct compat_semid64_ds_t {
    pub sem_perm: compat_ipc64_perm_t,
    pub sem_otime: compat_ulong_t,
    pub sem_otime_high: compat_ulong_t,
    pub sem_ctime: compat_ulong_t,
    pub sem_ctime_high: compat_ulong_t,
    pub sem_nsems: compat_ulong_t,
    __unused3: compat_ulong_t,
    __unused4: compat_ulong_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct compat_msqid64_ds_t {
    pub msg_perm: compat_ipc64_perm_t,
    pub msg_stime: compat_ulong_t,
    pub msg_stime_high: compat_ulong_t,
    pub msg_rtime: compat_ulong_t,
    pub msg_rtime_high: compat_ulong_t,
    pub msg_ctime: compat_ulong_t,
    pub msg_ctime_high: compat_ulong_t,
    pub msg_cbytes: compat_ulong_t,
    pub msg_qnum: compat_ulong_t,
    pub msg_qbytes: compat_ulong_t,
    pub msg_lspid: compat_pid_t,
    pub msg_lrpid: compat_pid_t,
    __unused4: compat_ulong_t,
    __unused5: compat_ulong_t,
}

#[repr(C)]
#[derive(Debug)]
pub struct compat_shmid64_ds_t {
    pub shm_perm: compat_ipc64_perm_t,
    pub shm_segsz: compat_size_t,
    pub shm_atime: compat_ulong_t,
    pub shm_atime_high: compat_ulong_t,
    pub shm_dtime: compat_ulong_t,
    pub shm_dtime_high: compat_ulong_t,
    pub shm_ctime: compat_ulong_t,
    pub shm_ctime_high: compat_ulong_t,
    pub shm_cpid: compat_pid_t,
    pub shm_lpid: compat_pid_t,
    pub shm_nattch: compat_ulong_t,
    __unused4: compat_ulong_t,
    __unused5: compat_ulong_t,
}

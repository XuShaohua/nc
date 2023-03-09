// Copyright (c) 2023 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `sys/param.h`

use super::syslimits::{ARG_MAX, CHILD_MAX, NGROUPS_MAX, OPEN_MAX, PATH_MAX};

/// System version (year & month).
pub const BSD: i32 = 199506;
pub const BSD4_3: i32 = 1;
pub const BSD4_4: i32 = 1;

pub const __FreeBSD_version: i32 = 1400077;

pub const P_OSREL_SIGWAIT: i32 = 700000;
pub const P_OSREL_SIGSEGV: i32 = 700004;
pub const P_OSREL_MAP_ANON: i32 = 800104;
pub const P_OSREL_MAP_FSTRICT: i32 = 1100036;
pub const P_OSREL_SHUTDOWN_ENOTCONN: i32 = 1100077;
pub const P_OSREL_MAP_GUARD: i32 = 1200035;
pub const P_OSREL_WRFSBASE: i32 = 1200041;
pub const P_OSREL_CK_CYLGRP: i32 = 1200046;
pub const P_OSREL_VMTOTAL64: i32 = 1200054;
pub const P_OSREL_CK_SUPERBLOCK: i32 = 1300000;
pub const P_OSREL_CK_INODE: i32 = 1300005;
pub const P_OSREL_POWERPC_NEW_AUX_ARGS: i32 = 1300070;

pub const fn P_OSREL_MAJOR(x: i32) -> i32 {
    x / 100000
}

/// max command name remembered
pub const MAXCOMLEN: uszie = 19;
/// max interpreter file name length
pub const MAXINTERP: usize = PATH_MAX;
/// max login name length (incl. NUL)
pub const MAXLOGNAME: usize = 33;
/// max simultaneous processes
pub const MAXUPRC: usize = CHILD_MAX;
/// max bytes for an exec function
pub const NCARGS: usize = ARG_MAX;
/// max number groups
pub const NGROUPS: usize = NGROUPS_MAX + 1;
/// max open files per process
pub const NOFILE: usize = OPEN_MAX;
/// marker for empty group set member
pub const NOGROUP: usize = 65535;
/// max hostname size
pub const MAXHOSTNAMELEN: usize = 256;
/// max length of devicename
pub const SPECNAMELEN: usize = 255;

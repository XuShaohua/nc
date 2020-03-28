// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// Disk quota - quotactl(2) commands for the XFS Quota Manager (XQM).

/// forms first QCMD argument
#[inline]
pub const fn XQM_CMD(x: i32) -> i32 {
    (('X' as i32) << 8) + (x)
}

/// test if for XFS
#[inline]
pub const fn XQM_COMMAND(x: i32) -> bool {
    (x & (0xff << 8)) == (('X' as i32) << 8)
}

/// system call user quota type
pub const XQM_USRQUOTA: i32 = 0;
/// system call group quota type
pub const XQM_GRPQUOTA: i32 = 1;
/// system call project quota type
pub const XQM_PRJQUOTA: i32 = 2;
pub const XQM_MAXQUOTAS: i32 = 3;

/// enable accounting/enforcement
pub const Q_XQUOTAON: i32 = XQM_CMD(1);
/// disable accounting/enforcement
pub const Q_XQUOTAOFF: i32 = XQM_CMD(2);
/// get disk limits and usage
pub const Q_XGETQUOTA: i32 = XQM_CMD(3);
/// set disk limits
pub const Q_XSETQLIM: i32 = XQM_CMD(4);
/// get quota subsystem status
pub const Q_XGETQSTAT: i32 = XQM_CMD(5);
/// free disk space used by dquots
pub const Q_XQUOTARM: i32 = XQM_CMD(6);
/// delalloc flush, updates dquots
pub const Q_XQUOTASYNC: i32 = XQM_CMD(7);
/// newer version of get quota
pub const Q_XGETQSTATV: i32 = XQM_CMD(8);
/// get disk limits and usage >= ID
pub const Q_XGETNEXTQUOTA: i32 = XQM_CMD(9);

/// fs_disk_quota structure:
///
/// This contains the current quota information regarding a user/proj/group.
/// It is 64-bit aligned, and all the blk units are in BBs (Basic Blocks) of
/// 512 bytes.
/// fs_disk_quota.d_version
pub const FS_DQUOT_VERSION: i32 = 1;

#[repr(C)]
pub struct fs_disk_quota_t {
    /// version of this structure
    pub d_version: i8,

    /// FS_{USER,PROJ,GROUP}_QUOTA
    pub d_flags: i8,

    /// field specifier
    pub d_fieldmask: u16,

    /// user, project, or group ID
    pub d_id: u32,

    /// absolute limit on disk blks
    pub d_blk_hardlimit: u64,

    /// preferred limit on disk blks
    pub d_blk_softlimit: u64,

    /// maximum # allocated inodes
    pub d_ino_hardlimit: u64,

    /// preferred inode limit
    pub d_ino_softlimit: u64,

    /// # disk blocks owned by the user
    pub d_bcount: u64,

    /// # inodes owned by the user
    pub d_icount: u64,

    /// zero if within inode limits if not, we refuse service
    pub d_itimer: i32,

    /// similar to above; for disk blocks
    pub d_btimer: i32,

    /// # warnings issued wrt num inodes
    pub d_iwarns: u16,

    /// # warnings issued wrt disk blocks
    pub d_bwarns: u16,

    /// padding2 - for future use
    pub d_padding2: i32,

    /// absolute limit on realtime blks
    pub d_rtb_hardlimit: u64,

    /// preferred limit on RT disk blks
    pub d_rtb_softlimit: u64,

    /// # realtime blocks owned
    pub d_rtbcount: u64,

    /// similar to above; for RT disk blks
    pub d_rtbtimer: i32,

    /// # warnings issued wrt RT disk blks
    pub d_rtbwarns: u16,

    /// padding3 - for future use
    pub d_padding3: i16,

    /// yet more padding
    d_padding4: [i8; 8],
}

/// These fields are sent to Q_XSETQLIM to specify fields that need to change.
pub const FS_DQ_ISOFT: i32 = 1;
pub const FS_DQ_IHARD: i32 = 1 << 1;
pub const FS_DQ_BSOFT: i32 = 1 << 2;
pub const FS_DQ_BHARD: i32 = 1 << 3;
pub const FS_DQ_RTBSOFT: i32 = 1 << 4;
pub const FS_DQ_RTBHARD: i32 = 1 << 5;
pub const FS_DQ_LIMIT_MASK: i32 =
    FS_DQ_ISOFT | FS_DQ_IHARD | FS_DQ_BSOFT | FS_DQ_BHARD | FS_DQ_RTBSOFT | FS_DQ_RTBHARD;
/// These timers can only be set in super user's dquot. For others, timers are
/// automatically started and stopped. Superusers timer values set the limits
/// for the rest.  In case these values are zero, the DQ_{F,B}TIMELIMIT values
/// defined below are used.
/// These values also apply only to the d_fieldmask field for Q_XSETQLIM.
pub const FS_DQ_BTIMER: i32 = 1 << 6;
pub const FS_DQ_ITIMER: i32 = 1 << 7;
pub const FS_DQ_RTBTIMER: i32 = 1 << 8;
pub const FS_DQ_TIMER_MASK: i32 = FS_DQ_BTIMER | FS_DQ_ITIMER | FS_DQ_RTBTIMER;

/// Warning counts are set in both super user's dquot and others. For others,
/// warnings are set/cleared by the administrators (or automatically by going
/// below the soft limit).  Superusers warning values set the warning limits
/// for the rest.  In case these values are zero, the DQ_{F,B}WARNLIMIT values
/// defined below are used.
/// These values also apply only to the d_fieldmask field for Q_XSETQLIM.
pub const FS_DQ_BWARNS: i32 = 1 << 9;
pub const FS_DQ_IWARNS: i32 = 1 << 10;
pub const FS_DQ_RTBWARNS: i32 = 1 << 11;
pub const FS_DQ_WARNS_MASK: i32 = FS_DQ_BWARNS | FS_DQ_IWARNS | FS_DQ_RTBWARNS;

/// Accounting values.  These can only be set for filesystem with
/// non-transactional quotas that require quotacheck(8) in userspace.
pub const FS_DQ_BCOUNT: i32 = 1 << 12;
pub const FS_DQ_ICOUNT: i32 = 1 << 13;
pub const FS_DQ_RTBCOUNT: i32 = 1 << 14;
pub const FS_DQ_ACCT_MASK: i32 = FS_DQ_BCOUNT | FS_DQ_ICOUNT | FS_DQ_RTBCOUNT;

/// Various flags related to quotactl(2).
/// user quota accounting
pub const FS_QUOTA_UDQ_ACCT: i32 = 1;
/// user quota limits enforcement
pub const FS_QUOTA_UDQ_ENFD: i32 = 1 << 1;
/// group quota accounting
pub const FS_QUOTA_GDQ_ACCT: i32 = 1 << 2;
/// group quota limits enforcement
pub const FS_QUOTA_GDQ_ENFD: i32 = 1 << 3;
/// project quota accounting
pub const FS_QUOTA_PDQ_ACCT: i32 = 1 << 4;
/// project quota limits enforcement
pub const FS_QUOTA_PDQ_ENFD: i32 = 1 << 5;

/// user quota type
pub const FS_USER_QUOTA: i32 = 1;
/// project quota type
pub const FS_PROJ_QUOTA: i32 = 1 << 1;
/// group quota type
pub const FS_GROUP_QUOTA: i32 = 1 << 2;

/// fs_quota_stat.qs_version
pub const FS_QSTAT_VERSION: i32 = 1;

/// Some basic information about 'quota files'.
#[repr(C)]
pub struct fs_qfilestat_t {
    /// inode number
    pub qfs_ino: u64,

    /// number of BBs 512-byte-blks
    pub qfs_nblks: u64,

    /// number of extents
    pub qfs_nextents: u32,
}

/// fs_quota_stat is the struct returned in Q_XGETQSTAT for a given file system.
/// Provides a centralized way to get meta information about the quota subsystem.
/// eg. space taken up for user and group quotas, number of dquots currently
/// incore.
#[repr(C)]
pub struct fs_quota_stat_t {
    /// version number for future changes
    pub qs_version: i8,

    /// FS_QUOTA_{U,P,G}DQ_{ACCT,ENFD}
    pub qs_flags: u16,

    /// unused
    pub qs_pad: i8,

    /// user quota storage information
    pub qs_uquota: fs_qfilestat_t,

    /// group quota storage information
    pub qs_gquota: fs_qfilestat_t,

    /// number of dquots incore
    pub qs_incoredqs: u32,

    /// limit for blks timer
    pub qs_btimelimit: i32,

    /// limit for inodes timer
    pub qs_itimelimit: i32,

    /// limit for rt blks timer
    pub qs_rtbtimelimit: i32,

    /// limit for num warnings
    pub qs_bwarnlimit: u16,

    /// limit for num warnings
    pub qs_iwarnlimit: u16,
}

/// fs_quota_statv.qs_version
pub const FS_QSTATV_VERSION1: i32 = 1;

/// Some basic information about 'quota files' for Q_XGETQSTATV command
#[repr(C)]
pub struct fs_qfilestatv_t {
    /// inode number
    pub qfs_ino: u64,

    /// number of BBs 512-byte-blks
    pub qfs_nblks: u64,

    /// number of extents
    pub qfs_nextents: u32,

    /// pad for 8-byte alignment
    qfs_pad: u32,
}

/// fs_quota_statv is used by Q_XGETQSTATV for a given file system. It provides
/// a centralized way to get meta information about the quota subsystem. eg.
/// space taken up for user, group, and project quotas, number of dquots
/// currently incore.
///
/// This version has proper versioning support with appropriate padding for
/// future expansions, and ability to expand for future without creating any
/// backward compatibility issues.
///
/// Q_XGETQSTATV uses the passed in value of the requested version via
/// fs_quota_statv.qs_version to determine the return data layout of
/// fs_quota_statv.  The kernel will fill the data fields relevant to that
/// version.
///
/// If kernel does not support user space caller specified version, EINVAL will
/// be returned. User space caller can then reduce the version number and retry
/// the same command.
#[repr(C)]
pub struct fs_quota_statv_t {
    /// version for future changes
    pub qs_version: i8,

    /// pad for 16bit alignment
    qs_pad1: u8,

    /// FS_QUOTA_.* flags
    pub qs_flags: u16,

    /// number of dquots incore
    pub qs_incoredqs: u32,

    /// user quota information
    pub qs_uquota: fs_qfilestat_t,

    /// group quota information
    pub qs_gquota: fs_qfilestat_t,

    /// project quota information
    pub qs_pquota: fs_qfilestat_t,

    /// limit for blks timer
    pub qs_btimelimit: i32,

    /// limit for inodes timer
    pub qs_itimelimit: i32,

    /// limit for rt blks timer
    pub qs_rtbtimelimit: i32,

    /// limit for num warnings
    pub qs_bwarnlimit: u16,

    /// limit for num warnings
    pub qs_iwarnlimit: u16,

    /// for future proofing
    qs_pad2: [u64; 8],
}

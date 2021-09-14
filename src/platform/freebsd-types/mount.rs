// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From sys/sys/mount.h

use crate::uid_t;

/// filesystem id type
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct fsid_t {
    pub val: [i32; 2],
}

/// File identifier.
///
/// These are unique per filesystem on a single machine.
///
/// Note that the offset of fid_data is 4 bytes, so care must be taken to avoid
/// undefined behavior accessing unaligned fields within an embedded struct.
pub const MAXFIDSZ: usize = 16;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct fid_t {
    /// length of data in bytes
    pub fid_len: u16,

    /// force longword alignment
    pub fid_data0: u16,

    /// data (variable length)
    pub fid_data: [u8; MAXFIDSZ],
}

/// filesystem statistics
/// length of type name including null
pub const MFSNAMELEN: usize = 16;
/// size of on/from name bufs
pub const MNAMELEN: usize = 1024;
/// current version number
pub const STATFS_VERSION: i32 = 0x20140518;

#[repr(C)]
#[derive(Debug)]
pub struct statfs_t {
    /// structure version number
    pub f_version: u32,

    /// type of filesystem
    pub f_type: u32,

    /// copy of mount exported flags
    pub f_flags: u64,

    /// filesystem fragment size
    pub f_bsize: u64,

    /// optimal transfer block size
    pub f_iosize: u64,

    /// total data blocks in filesystem
    pub f_blocks: u64,

    /// free blocks in filesystem
    pub f_bfree: u64,

    /// free blocks avail to non-superuser
    pub f_bavail: i64,

    /// total file nodes in filesystem
    pub f_files: u64,

    /// free nodes avail to non-superuser
    pub f_ffree: i64,

    /// count of sync writes since mount
    pub f_syncwrites: u64,

    /// count of async writes since mount
    pub f_asyncwrites: u64,

    /// count of sync reads since mount
    pub f_syncreads: u64,

    /// count of async reads since mount
    pub f_asyncreads: u64,

    /// unused spare
    pub f_spare: [u64; 10],

    /// maximum filename length
    pub f_namemax: u32,

    /// user that mounted the filesystem
    pub f_owner: uid_t,

    /// filesystem id
    pub f_fsid: fsid_t,

    /// spare string space
    pub f_charspare: [u8; 80],

    /// filesystem type name
    pub f_fstypename: [u8; MFSNAMELEN],

    /// mounted filesystem
    pub f_mntfromname: [u8; MNAMELEN],

    /// directory on which mounted
    pub f_mntonname: [u8; MNAMELEN],
}

impl Default for statfs_t {
    fn default() -> Self {
        Self {
            f_version: 0,
            f_type: 0,
            f_flags: 0,
            f_bsize: 0,
            f_iosize: 0,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_syncwrites: 0,
            f_asyncwrites: 0,
            f_syncreads: 0,
            f_asyncreads: 0,
            f_spare: [0; 10],
            f_namemax: 0,
            f_owner: 0,
            f_fsid: fsid_t::default(),
            f_charspare: [0; 80],
            f_fstypename: [0; MFSNAMELEN],
            f_mntfromname: [0; MNAMELEN],
            f_mntonname: [0; MNAMELEN],
        }
    }
}

/// User specifiable flags, stored in mnt_flag.
/// read only filesystem
pub const MNT_RDONLY: u64 = 0x0000000000000001;
/// fs written synchronously
pub const MNT_SYNCHRONOUS: u64 = 0x0000000000000002;
/// can't exec from filesystem
pub const MNT_NOEXEC: u64 = 0x0000000000000004;
/// don't honor setuid fs bits
pub const MNT_NOSUID: u64 = 0x0000000000000008;
/// enable NFS version 4 ACLs
pub const MNT_NFS4ACLS: u64 = 0x0000000000000010;
/// union with underlying fs
pub const MNT_UNION: u64 = 0x0000000000000020;
/// fs written asynchronously
pub const MNT_ASYNC: u64 = 0x0000000000000040;
/// special SUID dir handling
pub const MNT_SUIDDIR: u64 = 0x0000000000100000;
/// using soft updates
pub const MNT_SOFTDEP: u64 = 0x0000000000200000;
/// do not follow symlinks
pub const MNT_NOSYMFOLLOW: u64 = 0x0000000000400000;
/// GEOM journal support enabled
pub const MNT_GJOURNAL: u64 = 0x0000000002000000;
/// MAC support for objects
pub const MNT_MULTILABEL: u64 = 0x0000000004000000;
/// ACL support enabled
pub const MNT_ACLS: u64 = 0x0000000008000000;
/// dont update file access time
pub const MNT_NOATIME: u64 = 0x0000000010000000;
/// disable cluster read
pub const MNT_NOCLUSTERR: u64 = 0x0000000040000000;
/// disable cluster write
pub const MNT_NOCLUSTERW: u64 = 0x0000000080000000;
/// using journaled soft updates
pub const MNT_SUJ: u64 = 0x0000000100000000;
/// mounted by automountd(8)
pub const MNT_AUTOMOUNTED: u64 = 0x0000000200000000;
/// filesys metadata untrusted
pub const MNT_UNTRUSTED: u64 = 0x0000000800000000;

/// NFS export related mount flags.
/// exported read only
pub const MNT_EXRDONLY: u64 = 0x0000000000000080;
/// filesystem is exported
pub const MNT_EXPORTED: u64 = 0x0000000000000100;
/// exported to the world
pub const MNT_DEFEXPORTED: u64 = 0x0000000000000200;
/// anon uid mapping for all
pub const MNT_EXPORTANON: u64 = 0x0000000000000400;
/// exported with Kerberos
pub const MNT_EXKERB: u64 = 0x0000000000000800;
/// public export (WebNFS)
pub const MNT_EXPUBLIC: u64 = 0x0000000020000000;
/// require TLS
pub const MNT_EXTLS: u64 = 0x0000004000000000;
/// require TLS with client cert
pub const MNT_EXTLSCERT: u64 = 0x0000008000000000;
/// require TLS with user cert
pub const MNT_EXTLSCERTUSER: u64 = 0x0000010000000000;

/// Flags set by internal operations, but visible to the user.
/// filesystem is stored locally
pub const MNT_LOCAL: u64 = 0x0000000000001000;
/// quotas are enabled on fs
pub const MNT_QUOTA: u64 = 0x0000000000002000;
/// identifies the root fs
pub const MNT_ROOTFS: u64 = 0x0000000000004000;
/// mounted by a user
pub const MNT_USER: u64 = 0x0000000000008000;
/// do not show entry in df
pub const MNT_IGNORE: u64 = 0x0000000000800000;
/// filesystem is verified
pub const MNT_VERIFIED: u64 = 0x0000000400000000;

/// Mask of flags that are visible to statfs().
pub const MNT_VISFLAGMASK: u64 = MNT_RDONLY
    | MNT_SYNCHRONOUS
    | MNT_NOEXEC
    | MNT_NOSUID
    | MNT_UNION
    | MNT_SUJ
    | MNT_ASYNC
    | MNT_EXRDONLY
    | MNT_EXPORTED
    | MNT_DEFEXPORTED
    | MNT_EXPORTANON
    | MNT_EXKERB
    | MNT_LOCAL
    | MNT_USER
    | MNT_QUOTA
    | MNT_ROOTFS
    | MNT_NOATIME
    | MNT_NOCLUSTERR
    | MNT_NOCLUSTERW
    | MNT_SUIDDIR
    | MNT_SOFTDEP
    | MNT_IGNORE
    | MNT_EXPUBLIC
    | MNT_NOSYMFOLLOW
    | MNT_GJOURNAL
    | MNT_MULTILABEL
    | MNT_ACLS
    | MNT_NFS4ACLS
    | MNT_AUTOMOUNTED
    | MNT_VERIFIED
    | MNT_UNTRUSTED;

/// Mask of flags that can be updated.
pub const MNT_UPDATEMASK: u64 = MNT_NOSUID
    | MNT_NOEXEC
    | MNT_SYNCHRONOUS
    | MNT_UNION
    | MNT_ASYNC
    | MNT_NOATIME
    | MNT_NOSYMFOLLOW
    | MNT_IGNORE
    | MNT_NOCLUSTERR
    | MNT_NOCLUSTERW
    | MNT_SUIDDIR
    | MNT_ACLS
    | MNT_USER
    | MNT_NFS4ACLS
    | MNT_AUTOMOUNTED
    | MNT_UNTRUSTED;

/// External filesystem command modifier flags.
/// Unmount can use the MNT_FORCE flag.
///
/// not real mount, just update
pub const MNT_UPDATE: u64 = 0x0000000000010000;
/// delete export host lists
pub const MNT_DELEXPORT: u64 = 0x0000000000020000;
/// reload filesystem data
pub const MNT_RELOAD: u64 = 0x0000000000040000;
/// force unmount or readonly
pub const MNT_FORCE: u64 = 0x0000000000080000;
/// snapshot the filesystem
pub const MNT_SNAPSHOT: u64 = 0x0000000001000000;
/// check vnode use counts.
pub const MNT_NONBUSY: u64 = 0x0000000004000000;
/// specify filesystem by ID.
pub const MNT_BYFSID: u64 = 0x0000000008000000;
/// Do not cover a mount point
pub const MNT_NOCOVER: u64 = 0x0000001000000000;
/// Only mount on empty dir
pub const MNT_EMPTYDIR: u64 = 0x0000002000000000;
/// recursively unmount uppers
pub const MNT_RECURSE: u64 = 0x0000100000000000;
/// unmount in async context
pub const MNT_DEFERRED: u64 = 0x0000200000000000;
pub const MNT_CMDFLAGS: u64 = MNT_UPDATE
    | MNT_DELEXPORT
    | MNT_RELOAD
    | MNT_FORCE
    | MNT_SNAPSHOT
    | MNT_NONBUSY
    | MNT_BYFSID
    | MNT_NOCOVER
    | MNT_EMPTYDIR
    | MNT_RECURSE
    | MNT_DEFERRED;

/// Internal filesystem control flags stored in mnt_kern_flag.
///
/// MNTK_UNMOUNT locks the mount entry so that name lookup cannot
/// proceed past the mount point.  This keeps the subtree stable during
/// mounts and unmounts.  When non-forced unmount flushes all vnodes
/// from the mp queue, the MNTK_UNMOUNT flag prevents insmntque() from
/// queueing new vnodes.
///
/// MNTK_UNMOUNTF permits filesystems to detect a forced unmount while
/// dounmount() is still waiting to lock the mountpoint. This allows
/// the filesystem to cancel operations that might otherwise deadlock
/// with the unmount attempt (used by NFS).
/// forced unmount in progress
pub const MNTK_UNMOUNTF: i32 = 0x00000001;
/// filtered async flag
pub const MNTK_ASYNC: i32 = 0x00000002;
/// async disabled by softdep
pub const MNTK_SOFTDEP: i32 = 0x00000004;
/// don't do msync
pub const MNTK_NOMSYNC: i32 = 0x00000008;
/// lock draining is happening
pub const MNTK_DRAINING: i32 = 0x00000010;
/// refcount expiring is happening
pub const MNTK_REFEXPIRE: i32 = 0x00000020;
/// Allow shared locking for more ops
pub const MNTK_EXTENDED_SHARED: i32 = 0x00000040;
/// Allow shared locking for writes
pub const MNTK_SHARED_WRITES: i32 = 0x00000080;
/// Disallow page faults during reads and writes.
///
/// Filesystem shall properly handle i/o state on EFAULT.
pub const MNTK_NO_IOPF: i32 = 0x00000100;
/// pending recursive unmount
pub const MNTK_RECURSE: i32 = 0x00000200;
/// waiting to drain MNTK_UPPER_PENDING
pub const MNTK_UPPER_WAITER: i32 = 0x00000400;
pub const MNTK_LOOKUP_EXCL_DOTDOT: i32 = 0x00000800;
pub const MNTK_UNMAPPED_BUFS: i32 = 0x00002000;
/// FS uses the buffer cache.
pub const MNTK_USES_BCACHE: i32 = 0x00004000;
/// Keep use ref for text
pub const MNTK_TEXT_REFS: i32 = 0x00008000;
pub const MNTK_VMSETSIZE_BUG: i32 = 0x00010000;
/// A hack for F_ISUNIONSTACK
pub const MNTK_UNIONFS: i32 = 0x00020000;
/// fast path lookup is supported
pub const MNTK_FPLOOKUP: i32 = 0x00040000;
/// Suspended by all-fs suspension
pub const MNTK_SUSPEND_ALL: i32 = 0x00080000;
/// Waiting on unmount taskqueue
pub const MNTK_TASKQUEUE_WAITER: i32 = 0x00100000;
/// disable async
pub const MNTK_NOASYNC: i32 = 0x00800000;
/// unmount in progress
pub const MNTK_UNMOUNT: i32 = 0x01000000;
/// waiting for unmount to finish
pub const MNTK_MWAIT: i32 = 0x02000000;
/// request write suspension
pub const MNTK_SUSPEND: i32 = 0x08000000;
/// block secondary writes
pub const MNTK_SUSPEND2: i32 = 0x04000000;
/// write operations are suspended
pub const MNTK_SUSPENDED: i32 = 0x10000000;
/// auto disable cache for nullfs mounts over this fs
pub const MNTK_N_NOCACHE: i32 = 0x20000000;
/// FS supports shared lock lookups
pub const MNTK_LOOKUP_SHARED: i32 = 0x40000000;
/// Don't send KNOTEs from VOP hooks
pub const MNTK_NOKNOTE: i32 = 0x80000000;

/// Flags for various system call interfaces.
///
/// waitfor flags to vfs_sync() and getfsstat()
/// synchronously wait for I/O to complete
pub const MNT_WAIT: i32 = 1;
/// start all I/O, but do not wait for it
pub const MNT_NOWAIT: i32 = 2;
/// push data not written by filesystem syncer
pub const MNT_LAZY: i32 = 3;
/// Suspend file system after sync
pub const MNT_SUSPEND: i32 = 4;

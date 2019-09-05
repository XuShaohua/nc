/// These are the fs-independent mount-flags: up to 32 flags are supported
///
/// Usage of these is restricted within the kernel to core mount(2) code and
/// callers of sys_mount() only.  Filesystems should be using the SB_*
/// equivalent instead.

/// Mount read-only
pub const MS_RDONLY: i32 = 1;
/// Ignore suid and sgid bits
pub const MS_NOSUID: i32 = 2;
/// Disallow access to device special files
pub const MS_NODEV: i32 = 4;
/// Disallow program execution
pub const MS_NOEXEC: i32 = 8;
/// Writes are synced at once
pub const MS_SYNCHRONOUS: i32 = 16;
/// Alter flags of a mounted FS
pub const MS_REMOUNT: i32 = 32;
/// Allow mandatory locks on an FS
pub const MS_MANDLOCK: i32 = 64;
/// Directory modifications are synchronous
pub const MS_DIRSYNC: i32 = 128;
/// Do not update access times.
pub const MS_NOATIME: i32 = 1024;
/// Do not update directory access times
pub const MS_NODIRATIME: i32 = 2048;
pub const MS_BIND: i32 = 4096;
pub const MS_MOVE: i32 = 8192;
pub const MS_REC: i32 = 16384;
/// MS_VERBOSE is deprecated.
pub const MS_VERBOSE: i32 = 32768;
pub const MS_SILENT: i32 = 32768;
/// VFS does not apply the umask
pub const MS_POSIXACL: i32 = (1 << 16);
/// change to unbindable
pub const MS_UNBINDABLE: i32 = (1 << 17);
/// change to private
pub const MS_PRIVATE: i32 = (1 << 18);
/// change to slave
pub const MS_SLAVE: i32 = (1 << 19);
/// change to shared
pub const MS_SHARED: i32 = (1 << 20);
/// Update atime relative to mtime/ctime.
pub const MS_RELATIME: i32 = (1 << 21);
/// this is a kern_mount call
pub const MS_KERNMOUNT: i32 = (1 << 22);
/// Update inode I_version field
pub const MS_I_VERSION: i32 = (1 << 23);
/// Always perform atime updates
pub const MS_STRICTATIME: i32 = (1 << 24);
/// Update the on-disk [acm]times lazily
pub const MS_LAZYTIME: i32 = (1 << 25);

/// These sb flags are internal to the kernel
pub const MS_SUBMOUNT: i32 = (1 << 26);
pub const MS_NOREMOTELOCK: i32 = (1 << 27);
pub const MS_NOSEC: i32 = (1 << 28);
pub const MS_BORN: i32 = (1 << 29);
pub const MS_ACTIVE: i32 = (1 << 30);
pub const MS_NOUSER: i32 = (1 << 31);

///  Superblock flags that can be altered by MS_REMOUNT
pub const MS_RMT_MASK: i32 =
    (MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME);

/// Old magic mount flag and mask
#[allow(overflowing_literals)]
pub const MS_MGC_VAL: i32 = 0xC0ED0000;
#[allow(overflowing_literals)]
pub const MS_MGC_MSK: i32 = 0xffff0000;

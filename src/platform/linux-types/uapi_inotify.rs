//! Inode based directory notification for Linux
//! Copyright (C) 2005 John McCutchan

use super::fcntl::{O_CLOEXEC, O_NONBLOCK};

/// struct inotify_event - structure read from the inotify device for each event
///
/// When you are watching a directory, you will receive the filename for events
/// such as IN_CREATE, IN_DELETE, IN_OPEN, IN_CLOSE, ..., relative to the wd.
#[repr(C)]
pub struct inotify_event_t {
    /// watch descriptor
    pub wd: u32,

    /// watch mask
    pub mask: u32,

    /// cookie to synchronize two events
    pub cookie: u32,

    /// length (including nulls) of name
    pub len: u32,

    /// stub for possible name
    pub name: usize,
}

/// the following are legal, implemented events that user-space can watch for
/// File was accessed
pub const IN_ACCESS: i32 = 0x00000001;

/// File was modified
pub const IN_MODIFY: i32 = 0x00000002;

/// Metadata changed
pub const IN_ATTRIB: i32 = 0x00000004;

/// Writtable file was closed
pub const IN_CLOSE_WRITE: i32 = 0x00000008;

/// Unwrittable file closed
pub const IN_CLOSE_NOWRITE: i32 = 0x00000010;

/// File was opened
pub const IN_OPEN: i32 = 0x00000020;

/// File was moved from X
pub const IN_MOVED_FROM: i32 = 0x00000040;

/// File was moved to Y
pub const IN_MOVED_TO: i32 = 0x00000080;

/// Subfile was created
pub const IN_CREATE: i32 = 0x00000100;

/// Subfile was deleted
pub const IN_DELETE: i32 = 0x00000200;

/// Self was deleted
pub const IN_DELETE_SELF: i32 = 0x00000400;

/// Self was moved
pub const IN_MOVE_SELF: i32 = 0x00000800;

/// the following are legal events.  they are sent as needed to any watch
/// Backing fs was unmounted
pub const IN_UNMOUNT: i32 = 0x00002000;

/// Event queued overflowed
pub const IN_Q_OVERFLOW: i32 = 0x00004000;

/// File was ignored
pub const IN_IGNORED: i32 = 0x00008000;

// helper events
/// close
pub const IN_CLOSE: i32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;

/// moves
pub const IN_MOVE: i32 = IN_MOVED_FROM | IN_MOVED_TO;

/// special flags
/// only watch the path if it is a directory
pub const IN_ONLYDIR: i32 = 0x01000000;

/// don't follow a sym link
pub const IN_DONT_FOLLOW: i32 = 0x02000000;

/// exclude events on unlinked objects
pub const IN_EXCL_UNLINK: i32 = 0x04000000;

/// only create watches
pub const IN_MASK_CREATE: i32 = 0x10000000;

/// add to the mask of an already existing watch
pub const IN_MASK_ADD: i32 = 0x20000000;

/// event occurred against dir
pub const IN_ISDIR: i32 = 0x40000000;

#[allow(overflowing_literals)]
/// only send event once
pub const IN_ONESHOT: i32 = 0x80000000;

/// All of the events - we build the list by hand so that we can add flags in
/// the future and not break backward compatibility.  Apps will get only the
/// events that they originally wanted.  Be sure to add new events here!
pub const IN_ALL_EVENTS: i32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE
    | IN_CREATE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

/// Flags for sys_inotify_init1.
pub const IN_CLOEXEC: i32 = O_CLOEXEC;
pub const IN_NONBLOCK: i32 = O_NONBLOCK;

// ioctl numbers: inotify uses 'I' prefix for all ioctls,
// except historical FIONREAD, which is based on 'T'.
//
// INOTIFY_IOC_SETNEXTWD: set desired number of next created
// watch descriptor.
//pub const INOTIFY_IOC_SETNEXTWD: i32 = _IOW;('I', 0, __s32)

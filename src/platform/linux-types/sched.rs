// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// cloning flags:
/// signal mask to be sent at exit
pub const CSIGNAL: i32 = 0x0000_00ff;
/// set if VM shared between processes
pub const CLONE_VM: i32 = 0x0000_0100;
/// set if fs info shared between processes
pub const CLONE_FS: i32 = 0x0000_0200;
/// set if open files shared between processes
pub const CLONE_FILES: i32 = 0x0000_0400;
/// set if signal handlers and blocked signals shared
pub const CLONE_SIGHAND: i32 = 0x0000_0800;
/// set if we want to let tracing continue on the child too
pub const CLONE_PTRACE: i32 = 0x0000_2000;
/// set if the parent wants the child to wake it up on mm_release
pub const CLONE_VFORK: i32 = 0x0000_4000;
/// set if we want to have the same parent as the cloner
pub const CLONE_PARENT: i32 = 0x0000_8000;
/// Same thread group?
pub const CLONE_THREAD: i32 = 0x0001_0000;
/// New mount namespace group
pub const CLONE_NEWNS: i32 = 0x0002_0000;
/// share system V SEM_UNDO semantics
pub const CLONE_SYSVSEM: i32 = 0x0004_0000;
/// create a new TLS for the child
pub const CLONE_SETTLS: i32 = 0x0008_0000;
/// set the TID in the parent
pub const CLONE_PARENT_SETTID: i32 = 0x0010_0000;
/// clear the TID in the child
pub const CLONE_CHILD_CLEARTID: i32 = 0x0020_0000;
/// Unused, ignored
pub const CLONE_DETACHED: i32 = 0x0040_0000;
/// set if the tracing process can't force CLONE_PTRACE on this clone
pub const CLONE_UNTRACED: i32 = 0x0080_0000;
/// set the TID in the child
pub const CLONE_CHILD_SETTID: i32 = 0x0100_0000;
/// New cgroup namespace
pub const CLONE_NEWCGROUP: i32 = 0x0200_0000;
/// New utsname namespace
pub const CLONE_NEWUTS: i32 = 0x0400_0000;
/// New ipc namespace
pub const CLONE_NEWIPC: i32 = 0x0800_0000;
/// New user namespace
pub const CLONE_NEWUSER: i32 = 0x1000_0000;
/// New pid namespace
pub const CLONE_NEWPID: i32 = 0x2000_0000;
/// New network namespace
pub const CLONE_NEWNET: i32 = 0x4000_0000;
/// Clone io context
#[allow(overflowing_literals)]
pub const CLONE_IO: i32 = 0x8000_0000;

/// Scheduling policies
pub const SCHED_NORMAL: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
pub const SCHED_BATCH: i32 = 3;
/// SCHED_ISO: reserved but not implemented yet
pub const SCHED_IDLE: i32 = 5;
pub const SCHED_DEADLINE: i32 = 6;

/// Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork
pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

/// For the sched_{set,get}attr() calls
pub const SCHED_FLAG_RESET_ON_FORK: i32 = 0x01;
pub const SCHED_FLAG_RECLAIM: i32 = 0x02;
pub const SCHED_FLAG_DL_OVERRUN: i32 = 0x04;

pub const SCHED_FLAG_ALL: i32 =
    SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN;

/// cloning flags:
/// signal mask to be sent at exit
pub const CSIGNAL: i32 = 0x000000ff;
/// set if VM shared between processes
pub const CLONE_VM: i32 = 0x00000100;
/// set if fs info shared between processes
pub const CLONE_FS: i32 = 0x00000200;
/// set if open files shared between processes
pub const CLONE_FILES: i32 = 0x00000400;
/// set if signal handlers and blocked signals shared
pub const CLONE_SIGHAND: i32 = 0x00000800;
/// set if we want to let tracing continue on the child too
pub const CLONE_PTRACE: i32 = 0x00002000;
/// set if the parent wants the child to wake it up on mm_release
pub const CLONE_VFORK: i32 = 0x00004000;
/// set if we want to have the same parent as the cloner
pub const CLONE_PARENT: i32 = 0x00008000;
/// Same thread group?
pub const CLONE_THREAD: i32 = 0x00010000;
/// New mount namespace group
pub const CLONE_NEWNS: i32 = 0x00020000;
/// share system V SEM_UNDO semantics
pub const CLONE_SYSVSEM: i32 = 0x00040000;
/// create a new TLS for the child
pub const CLONE_SETTLS: i32 = 0x00080000;
/// set the TID in the parent
pub const CLONE_PARENT_SETTID: i32 = 0x00100000;
/// clear the TID in the child
pub const CLONE_CHILD_CLEARTID: i32 = 0x00200000;
/// Unused, ignored
pub const CLONE_DETACHED: i32 = 0x00400000;
/// set if the tracing process can't force CLONE_PTRACE on this clone
pub const CLONE_UNTRACED: i32 = 0x00800000;
/// set the TID in the child
pub const CLONE_CHILD_SETTID: i32 = 0x01000000;
/// New cgroup namespace
pub const CLONE_NEWCGROUP: i32 = 0x02000000;
/// New utsname namespace
pub const CLONE_NEWUTS: i32 = 0x04000000;
/// New ipc namespace
pub const CLONE_NEWIPC: i32 = 0x08000000;
/// New user namespace
pub const CLONE_NEWUSER: i32 = 0x10000000;
/// New pid namespace
pub const CLONE_NEWPID: i32 = 0x20000000;
/// New network namespace
pub const CLONE_NEWNET: i32 = 0x40000000;
/// Clone io context
#[allow(overflowing_literals)]
pub const CLONE_IO: i32 = 0x80000000;

/// Scheduling policies
pub const SCHED_NORMAL: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
pub const SCHED_BATCH: i32 = 3;
/// SCHED_ISO: reserved but not implemented yet
pub const SCHED_IDLE: i32 = 5;
pub const SCHED_DEADLINE: i32 = 6;

/// Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork
pub const SCHED_RESET_ON_FORK: i32 = 0x40000000;

/// For the sched_{set,get}attr() calls
pub const SCHED_FLAG_RESET_ON_FORK: i32 = 0x01;
pub const SCHED_FLAG_RECLAIM: i32 = 0x02;
pub const SCHED_FLAG_DL_OVERRUN: i32 = 0x04;

pub const SCHED_FLAG_ALL: i32 =
    (SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN);

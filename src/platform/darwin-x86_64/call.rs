// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::wildcard_imports)]
#![allow(non_snake_case)]

extern crate alloc;

use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

pub unsafe fn abort_with_payload() {
    core::unimplemented!();
    // syscall0(SYS_ABORT_WITH_PAYLOAD);
}

pub unsafe fn accept() {
    core::unimplemented!();
    // syscall0(SYS_ACCEPT);
}

pub unsafe fn accept_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_ACCEPT_NOCANCEL);
}

pub unsafe fn access() {
    core::unimplemented!();
    // syscall0(SYS_ACCESS);
}

pub unsafe fn access_extended() {
    core::unimplemented!();
    // syscall0(SYS_ACCESS_EXTENDED);
}

pub unsafe fn acct() {
    core::unimplemented!();
    // syscall0(SYS_ACCT);
}

pub unsafe fn adjtime() {
    core::unimplemented!();
    // syscall0(SYS_ADJTIME);
}

pub unsafe fn aio_cancel() {
    core::unimplemented!();
    // syscall0(SYS_AIO_CANCEL);
}

pub unsafe fn aio_error() {
    core::unimplemented!();
    // syscall0(SYS_AIO_ERROR);
}

pub unsafe fn aio_fsync() {
    core::unimplemented!();
    // syscall0(SYS_AIO_FSYNC);
}

pub unsafe fn aio_read() {
    core::unimplemented!();
    // syscall0(SYS_AIO_READ);
}

pub unsafe fn aio_return() {
    core::unimplemented!();
    // syscall0(SYS_AIO_RETURN);
}

pub unsafe fn aio_suspend() {
    core::unimplemented!();
    // syscall0(SYS_AIO_SUSPEND);
}

pub unsafe fn aio_suspend_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_AIO_SUSPEND_NOCANCEL);
}

pub unsafe fn aio_write() {
    core::unimplemented!();
    // syscall0(SYS_AIO_WRITE);
}

pub unsafe fn audit() {
    core::unimplemented!();
    // syscall0(SYS_AUDIT);
}

pub unsafe fn auditctl() {
    core::unimplemented!();
    // syscall0(SYS_AUDITCTL);
}

pub unsafe fn auditon() {
    core::unimplemented!();
    // syscall0(SYS_AUDITON);
}

pub unsafe fn audit_session_join() {
    core::unimplemented!();
    // syscall0(SYS_AUDIT_SESSION_JOIN);
}

pub unsafe fn audit_session_port() {
    core::unimplemented!();
    // syscall0(SYS_AUDIT_SESSION_PORT);
}

pub unsafe fn audit_session_self() {
    core::unimplemented!();
    // syscall0(SYS_AUDIT_SESSION_SELF);
}

pub unsafe fn bind() {
    core::unimplemented!();
    // syscall0(SYS_BIND);
}

pub unsafe fn bsdthread_create() {
    core::unimplemented!();
    // syscall0(SYS_BSDTHREAD_CREATE);
}

pub unsafe fn bsdthread_ctl() {
    core::unimplemented!();
    // syscall0(SYS_BSDTHREAD_CTL);
}

pub unsafe fn bsdthread_register() {
    core::unimplemented!();
    // syscall0(SYS_BSDTHREAD_REGISTER);
}

pub unsafe fn bsdthread_terminate() {
    core::unimplemented!();
    // syscall0(SYS_BSDTHREAD_TERMINATE);
}

pub unsafe fn change_fdguard_np() {
    core::unimplemented!();
    // syscall0(SYS_CHANGE_FDGUARD_NP);
}

pub unsafe fn chdir() {
    core::unimplemented!();
    // syscall0(SYS_CHDIR);
}

pub unsafe fn chflags() {
    core::unimplemented!();
    // syscall0(SYS_CHFLAGS);
}

pub unsafe fn chmod() {
    core::unimplemented!();
    // syscall0(SYS_CHMOD);
}

pub unsafe fn chmod_extended() {
    core::unimplemented!();
    // syscall0(SYS_CHMOD_EXTENDED);
}

pub unsafe fn chown() {
    core::unimplemented!();
    // syscall0(SYS_CHOWN);
}

pub unsafe fn chroot() {
    core::unimplemented!();
    // syscall0(SYS_CHROOT);
}

pub unsafe fn clonefileat() {
    core::unimplemented!();
    // syscall0(SYS_CLONEFILEAT);
}

pub unsafe fn close() {
    core::unimplemented!();
    // syscall0(SYS_CLOSE);
}

pub unsafe fn close_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_CLOSE_NOCANCEL);
}

pub unsafe fn coalition() {
    core::unimplemented!();
    // syscall0(SYS_COALITION);
}

pub unsafe fn coalition_info() {
    core::unimplemented!();
    // syscall0(SYS_COALITION_INFO);
}

pub unsafe fn coalition_ledger() {
    core::unimplemented!();
    // syscall0(SYS_COALITION_LEDGER);
}

pub unsafe fn connect() {
    core::unimplemented!();
    // syscall0(SYS_CONNECT);
}

pub unsafe fn connectx() {
    core::unimplemented!();
    // syscall0(SYS_CONNECTX);
}

pub unsafe fn connect_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_CONNECT_NOCANCEL);
}

pub unsafe fn copyfile() {
    core::unimplemented!();
    // syscall0(SYS_COPYFILE);
}

pub unsafe fn csops() {
    core::unimplemented!();
    // syscall0(SYS_CSOPS);
}

pub unsafe fn csops_audittoken() {
    core::unimplemented!();
    // syscall0(SYS_CSOPS_AUDITTOKEN);
}

pub unsafe fn csrctl() {
    core::unimplemented!();
    // syscall0(SYS_CSRCTL);
}

pub unsafe fn delete() {
    core::unimplemented!();
    // syscall0(SYS_DELETE);
}

pub unsafe fn disconnectx() {
    core::unimplemented!();
    // syscall0(SYS_DISCONNECTX);
}

pub unsafe fn dup() {
    core::unimplemented!();
    // syscall0(SYS_DUP);
}

pub unsafe fn dup2() {
    core::unimplemented!();
    // syscall0(SYS_DUP2);
}

pub unsafe fn exchangedata() {
    core::unimplemented!();
    // syscall0(SYS_EXCHANGEDATA);
}

pub unsafe fn execve() {
    core::unimplemented!();
    // syscall0(SYS_EXECVE);
}
/// Terminate current process.
///
/// ```
/// nc::exit(0);
/// ```
pub unsafe fn exit(status: i32) {
    let status = status as usize;
    let _ret = syscall1(SYS_EXIT, status);
    unreachable!();
}

pub unsafe fn faccessat() {
    core::unimplemented!();
    // syscall0(SYS_FACCESSAT);
}

pub unsafe fn fchdir() {
    core::unimplemented!();
    // syscall0(SYS_FCHDIR);
}

pub unsafe fn fchflags() {
    core::unimplemented!();
    // syscall0(SYS_FCHFLAGS);
}

pub unsafe fn fchmod() {
    core::unimplemented!();
    // syscall0(SYS_FCHMOD);
}

pub unsafe fn fchmodat() {
    core::unimplemented!();
    // syscall0(SYS_FCHMODAT);
}

pub unsafe fn fchmod_extended() {
    core::unimplemented!();
    // syscall0(SYS_FCHMOD_EXTENDED);
}

pub unsafe fn fchown() {
    core::unimplemented!();
    // syscall0(SYS_FCHOWN);
}

pub unsafe fn fchownat() {
    core::unimplemented!();
    // syscall0(SYS_FCHOWNAT);
}

pub unsafe fn fclonefileat() {
    core::unimplemented!();
    // syscall0(SYS_FCLONEFILEAT);
}

pub unsafe fn fcntl() {
    core::unimplemented!();
    // syscall0(SYS_FCNTL);
}

pub unsafe fn fcntl_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_FCNTL_NOCANCEL);
}

pub unsafe fn fdatasync() {
    core::unimplemented!();
    // syscall0(SYS_FDATASYNC);
}

pub unsafe fn ffsctl() {
    core::unimplemented!();
    // syscall0(SYS_FFSCTL);
}

pub unsafe fn fgetattrlist() {
    core::unimplemented!();
    // syscall0(SYS_FGETATTRLIST);
}

pub unsafe fn fgetxattr() {
    core::unimplemented!();
    // syscall0(SYS_FGETXATTR);
}

pub unsafe fn fhopen() {
    core::unimplemented!();
    // syscall0(SYS_FHOPEN);
}

pub unsafe fn fileport_makefd() {
    core::unimplemented!();
    // syscall0(SYS_FILEPORT_MAKEFD);
}

pub unsafe fn fileport_makeport() {
    core::unimplemented!();
    // syscall0(SYS_FILEPORT_MAKEPORT);
}

pub unsafe fn flistxattr() {
    core::unimplemented!();
    // syscall0(SYS_FLISTXATTR);
}

pub unsafe fn flock() {
    core::unimplemented!();
    // syscall0(SYS_FLOCK);
}

pub unsafe fn fmount() {
    core::unimplemented!();
    // syscall0(SYS_FMOUNT);
}

pub unsafe fn fork() {
    core::unimplemented!();
    // syscall0(SYS_FORK);
}

pub unsafe fn fpathconf() {
    core::unimplemented!();
    // syscall0(SYS_FPATHCONF);
}

pub unsafe fn fremovexattr() {
    core::unimplemented!();
    // syscall0(SYS_FREMOVEXATTR);
}

pub unsafe fn fsctl() {
    core::unimplemented!();
    // syscall0(SYS_FSCTL);
}

pub unsafe fn fsetattrlist() {
    core::unimplemented!();
    // syscall0(SYS_FSETATTRLIST);
}

pub unsafe fn fsetxattr() {
    core::unimplemented!();
    // syscall0(SYS_FSETXATTR);
}

pub unsafe fn fsgetpath() {
    core::unimplemented!();
    // syscall0(SYS_FSGETPATH);
}

pub unsafe fn fsgetpath_ext() {
    core::unimplemented!();
    // syscall0(SYS_FSGETPATH_EXT);
}

pub unsafe fn fstat() {
    core::unimplemented!();
    // syscall0(SYS_FSTAT);
}

pub unsafe fn fstat64() {
    core::unimplemented!();
    // syscall0(SYS_FSTAT64);
}

pub unsafe fn fstat64_extended() {
    core::unimplemented!();
    // syscall0(SYS_FSTAT64_EXTENDED);
}

pub unsafe fn fstatat() {
    core::unimplemented!();
    // syscall0(SYS_FSTATAT);
}

pub unsafe fn fstatat64() {
    core::unimplemented!();
    // syscall0(SYS_FSTATAT64);
}

pub unsafe fn fstatfs() {
    core::unimplemented!();
    // syscall0(SYS_FSTATFS);
}

pub unsafe fn fstatfs64() {
    core::unimplemented!();
    // syscall0(SYS_FSTATFS64);
}

pub unsafe fn fstat_extended() {
    core::unimplemented!();
    // syscall0(SYS_FSTAT_EXTENDED);
}

pub unsafe fn fsync() {
    core::unimplemented!();
    // syscall0(SYS_FSYNC);
}

pub unsafe fn fsync_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_FSYNC_NOCANCEL);
}

pub unsafe fn fs_snapshot() {
    core::unimplemented!();
    // syscall0(SYS_FS_SNAPSHOT);
}

pub unsafe fn ftruncate() {
    core::unimplemented!();
    // syscall0(SYS_FTRUNCATE);
}

pub unsafe fn futimes() {
    core::unimplemented!();
    // syscall0(SYS_FUTIMES);
}

pub unsafe fn getattrlist() {
    core::unimplemented!();
    // syscall0(SYS_GETATTRLIST);
}

pub unsafe fn getattrlistat() {
    core::unimplemented!();
    // syscall0(SYS_GETATTRLISTAT);
}

pub unsafe fn getattrlistbulk() {
    core::unimplemented!();
    // syscall0(SYS_GETATTRLISTBULK);
}

pub unsafe fn getaudit_addr() {
    core::unimplemented!();
    // syscall0(SYS_GETAUDIT_ADDR);
}

pub unsafe fn getauid() {
    core::unimplemented!();
    // syscall0(SYS_GETAUID);
}

pub unsafe fn getdirentries() {
    core::unimplemented!();
    // syscall0(SYS_GETDIRENTRIES);
}

pub unsafe fn getdirentries64() {
    core::unimplemented!();
    // syscall0(SYS_GETDIRENTRIES64);
}

pub unsafe fn getdirentriesattr() {
    core::unimplemented!();
    // syscall0(SYS_GETDIRENTRIESATTR);
}

pub unsafe fn getdtablesize() {
    core::unimplemented!();
    // syscall0(SYS_GETDTABLESIZE);
}

pub unsafe fn getegid() {
    core::unimplemented!();
    // syscall0(SYS_GETEGID);
}

pub unsafe fn getentropy() {
    core::unimplemented!();
    // syscall0(SYS_GETENTROPY);
}

pub unsafe fn geteuid() {
    core::unimplemented!();
    // syscall0(SYS_GETEUID);
}

pub unsafe fn getfh() {
    core::unimplemented!();
    // syscall0(SYS_GETFH);
}

pub unsafe fn getfsstat() {
    core::unimplemented!();
    // syscall0(SYS_GETFSSTAT);
}

pub unsafe fn getfsstat64() {
    core::unimplemented!();
    // syscall0(SYS_GETFSSTAT64);
}

pub unsafe fn getgid() {
    core::unimplemented!();
    // syscall0(SYS_GETGID);
}

pub unsafe fn getgroups() {
    core::unimplemented!();
    // syscall0(SYS_GETGROUPS);
}

pub unsafe fn gethostuuid() {
    core::unimplemented!();
    // syscall0(SYS_GETHOSTUUID);
}

pub unsafe fn getitimer() {
    core::unimplemented!();
    // syscall0(SYS_GETITIMER);
}

pub unsafe fn getlogin() {
    core::unimplemented!();
    // syscall0(SYS_GETLOGIN);
}

pub unsafe fn getpeername() {
    core::unimplemented!();
    // syscall0(SYS_GETPEERNAME);
}

pub unsafe fn getpgid() {
    core::unimplemented!();
    // syscall0(SYS_GETPGID);
}

pub unsafe fn getpgrp() {
    core::unimplemented!();
    // syscall0(SYS_GETPGRP);
}

pub unsafe fn getpid() {
    core::unimplemented!();
    // syscall0(SYS_GETPID);
}

pub unsafe fn getppid() {
    core::unimplemented!();
    // syscall0(SYS_GETPPID);
}

pub unsafe fn getpriority() {
    core::unimplemented!();
    // syscall0(SYS_GETPRIORITY);
}

pub unsafe fn getrlimit() {
    core::unimplemented!();
    // syscall0(SYS_GETRLIMIT);
}

pub unsafe fn getrusage() {
    core::unimplemented!();
    // syscall0(SYS_GETRUSAGE);
}

pub unsafe fn getsgroups() {
    core::unimplemented!();
    // syscall0(SYS_GETSGROUPS);
}

pub unsafe fn getsid() {
    core::unimplemented!();
    // syscall0(SYS_GETSID);
}

pub unsafe fn getsockname() {
    core::unimplemented!();
    // syscall0(SYS_GETSOCKNAME);
}

pub unsafe fn getsockopt() {
    core::unimplemented!();
    // syscall0(SYS_GETSOCKOPT);
}

pub unsafe fn gettid() {
    core::unimplemented!();
    // syscall0(SYS_GETTID);
}

pub unsafe fn gettimeofday() {
    core::unimplemented!();
    // syscall0(SYS_GETTIMEOFDAY);
}

pub unsafe fn getuid() {
    core::unimplemented!();
    // syscall0(SYS_GETUID);
}

pub unsafe fn getwgroups() {
    core::unimplemented!();
    // syscall0(SYS_GETWGROUPS);
}

pub unsafe fn getxattr() {
    core::unimplemented!();
    // syscall0(SYS_GETXATTR);
}

pub unsafe fn grab_pgo_data() {
    core::unimplemented!();
    // syscall0(SYS_GRAB_PGO_DATA);
}

pub unsafe fn guarded_close_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_CLOSE_NP);
}

pub unsafe fn guarded_kqueue_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_KQUEUE_NP);
}

pub unsafe fn guarded_open_dprotected_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_OPEN_DPROTECTED_NP);
}

pub unsafe fn guarded_open_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_OPEN_NP);
}

pub unsafe fn guarded_pwrite_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_PWRITE_NP);
}

pub unsafe fn guarded_writev_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_WRITEV_NP);
}

pub unsafe fn guarded_write_np() {
    core::unimplemented!();
    // syscall0(SYS_GUARDED_WRITE_NP);
}

pub unsafe fn identitysvc() {
    core::unimplemented!();
    // syscall0(SYS_IDENTITYSVC);
}

pub unsafe fn initgroups() {
    core::unimplemented!();
    // syscall0(SYS_INITGROUPS);
}

pub unsafe fn invalid() {
    core::unimplemented!();
    // syscall0(SYS_INVALID);
}

pub unsafe fn ioctl() {
    core::unimplemented!();
    // syscall0(SYS_IOCTL);
}

pub unsafe fn iopolicysys() {
    core::unimplemented!();
    // syscall0(SYS_IOPOLICYSYS);
}

pub unsafe fn issetugid() {
    core::unimplemented!();
    // syscall0(SYS_ISSETUGID);
}

pub unsafe fn kas_info() {
    core::unimplemented!();
    // syscall0(SYS_KAS_INFO);
}

pub unsafe fn kdebug_trace() {
    core::unimplemented!();
    // syscall0(SYS_KDEBUG_TRACE);
}

pub unsafe fn kdebug_trace64() {
    core::unimplemented!();
    // syscall0(SYS_KDEBUG_TRACE64);
}

pub unsafe fn kdebug_trace_string() {
    core::unimplemented!();
    // syscall0(SYS_KDEBUG_TRACE_STRING);
}

pub unsafe fn kdebug_typefilter() {
    core::unimplemented!();
    // syscall0(SYS_KDEBUG_TYPEFILTER);
}

pub unsafe fn kevent() {
    core::unimplemented!();
    // syscall0(SYS_KEVENT);
}

pub unsafe fn kevent64() {
    core::unimplemented!();
    // syscall0(SYS_KEVENT64);
}

pub unsafe fn kevent_id() {
    core::unimplemented!();
    // syscall0(SYS_KEVENT_ID);
}

pub unsafe fn kevent_qos() {
    core::unimplemented!();
    // syscall0(SYS_KEVENT_QOS);
}

pub unsafe fn kill() {
    core::unimplemented!();
    // syscall0(SYS_KILL);
}

pub unsafe fn kqueue() {
    core::unimplemented!();
    // syscall0(SYS_KQUEUE);
}

pub unsafe fn kqueue_workloop_ctl() {
    core::unimplemented!();
    // syscall0(SYS_KQUEUE_WORKLOOP_CTL);
}

pub unsafe fn lchown() {
    core::unimplemented!();
    // syscall0(SYS_LCHOWN);
}

pub unsafe fn ledger() {
    core::unimplemented!();
    // syscall0(SYS_LEDGER);
}

pub unsafe fn link() {
    core::unimplemented!();
    // syscall0(SYS_LINK);
}

pub unsafe fn linkat() {
    core::unimplemented!();
    // syscall0(SYS_LINKAT);
}

pub unsafe fn lio_listio() {
    core::unimplemented!();
    // syscall0(SYS_LIO_LISTIO);
}

pub unsafe fn listen() {
    core::unimplemented!();
    // syscall0(SYS_LISTEN);
}

pub unsafe fn listxattr() {
    core::unimplemented!();
    // syscall0(SYS_LISTXATTR);
}

pub unsafe fn log_data() {
    core::unimplemented!();
    // syscall0(SYS_LOG_DATA);
}

pub unsafe fn lseek() {
    core::unimplemented!();
    // syscall0(SYS_LSEEK);
}

pub unsafe fn lstat() {
    core::unimplemented!();
    // syscall0(SYS_LSTAT);
}

pub unsafe fn lstat64() {
    core::unimplemented!();
    // syscall0(SYS_LSTAT64);
}

pub unsafe fn lstat64_extended() {
    core::unimplemented!();
    // syscall0(SYS_LSTAT64_EXTENDED);
}

pub unsafe fn lstat_extended() {
    core::unimplemented!();
    // syscall0(SYS_LSTAT_EXTENDED);
}

pub unsafe fn mach_eventlink_signal() {
    core::unimplemented!();
    // syscall0(SYS_MACH_EVENTLINK_SIGNAL);
}

pub unsafe fn mach_eventlink_signal_wait_until() {
    core::unimplemented!();
    // syscall0(SYS_MACH_EVENTLINK_SIGNAL_WAIT_UNTIL);
}

pub unsafe fn mach_eventlink_wait_until() {
    core::unimplemented!();
    // syscall0(SYS_MACH_EVENTLINK_WAIT_UNTIL);
}

pub unsafe fn madvise() {
    core::unimplemented!();
    // syscall0(SYS_MADVISE);
}

pub unsafe fn memorystatus_available_memory() {
    core::unimplemented!();
    // syscall0(SYS_MEMORYSTATUS_AVAILABLE_MEMORY);
}

pub unsafe fn memorystatus_control() {
    core::unimplemented!();
    // syscall0(SYS_MEMORYSTATUS_CONTROL);
}

pub unsafe fn memorystatus_get_level() {
    core::unimplemented!();
    // syscall0(SYS_MEMORYSTATUS_GET_LEVEL);
}

pub unsafe fn microstackshot() {
    core::unimplemented!();
    // syscall0(SYS_MICROSTACKSHOT);
}

pub unsafe fn mincore() {
    core::unimplemented!();
    // syscall0(SYS_MINCORE);
}

pub unsafe fn minherit() {
    core::unimplemented!();
    // syscall0(SYS_MINHERIT);
}

pub unsafe fn mkdir() {
    core::unimplemented!();
    // syscall0(SYS_MKDIR);
}

pub unsafe fn mkdirat() {
    core::unimplemented!();
    // syscall0(SYS_MKDIRAT);
}

pub unsafe fn mkdir_extended() {
    core::unimplemented!();
    // syscall0(SYS_MKDIR_EXTENDED);
}

pub unsafe fn mkfifo() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFO);
}

pub unsafe fn mkfifo_extended() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFO_EXTENDED);
}

pub unsafe fn mknod() {
    core::unimplemented!();
    // syscall0(SYS_MKNOD);
}

pub unsafe fn mlock() {
    core::unimplemented!();
    // syscall0(SYS_MLOCK);
}

pub unsafe fn mlockall() {
    core::unimplemented!();
    // syscall0(SYS_MLOCKALL);
}

pub unsafe fn mmap() {
    core::unimplemented!();
    // syscall0(SYS_MMAP);
}

pub unsafe fn mount() {
    core::unimplemented!();
    // syscall0(SYS_MOUNT);
}

pub unsafe fn mprotect() {
    core::unimplemented!();
    // syscall0(SYS_MPROTECT);
}

pub unsafe fn mremap_encrypted() {
    core::unimplemented!();
    // syscall0(SYS_MREMAP_ENCRYPTED);
}

pub unsafe fn msgctl() {
    core::unimplemented!();
    // syscall0(SYS_MSGCTL);
}

pub unsafe fn msgget() {
    core::unimplemented!();
    // syscall0(SYS_MSGGET);
}

pub unsafe fn msgrcv() {
    core::unimplemented!();
    // syscall0(SYS_MSGRCV);
}

pub unsafe fn msgrcv_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_MSGRCV_NOCANCEL);
}

pub unsafe fn msgsnd() {
    core::unimplemented!();
    // syscall0(SYS_MSGSND);
}

pub unsafe fn msgsnd_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_MSGSND_NOCANCEL);
}

pub unsafe fn msgsys() {
    core::unimplemented!();
    // syscall0(SYS_MSGSYS);
}

pub unsafe fn msync() {
    core::unimplemented!();
    // syscall0(SYS_MSYNC);
}

pub unsafe fn msync_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_MSYNC_NOCANCEL);
}

pub unsafe fn munlock() {
    core::unimplemented!();
    // syscall0(SYS_MUNLOCK);
}

pub unsafe fn munlockall() {
    core::unimplemented!();
    // syscall0(SYS_MUNLOCKALL);
}

pub unsafe fn munmap() {
    core::unimplemented!();
    // syscall0(SYS_MUNMAP);
}

pub unsafe fn necp_client_action() {
    core::unimplemented!();
    // syscall0(SYS_NECP_CLIENT_ACTION);
}

pub unsafe fn necp_match_policy() {
    core::unimplemented!();
    // syscall0(SYS_NECP_MATCH_POLICY);
}

pub unsafe fn necp_open() {
    core::unimplemented!();
    // syscall0(SYS_NECP_OPEN);
}

pub unsafe fn necp_session_action() {
    core::unimplemented!();
    // syscall0(SYS_NECP_SESSION_ACTION);
}

pub unsafe fn necp_session_open() {
    core::unimplemented!();
    // syscall0(SYS_NECP_SESSION_OPEN);
}

pub unsafe fn netagent_trigger() {
    core::unimplemented!();
    // syscall0(SYS_NETAGENT_TRIGGER);
}

pub unsafe fn net_qos_guideline() {
    core::unimplemented!();
    // syscall0(SYS_NET_QOS_GUIDELINE);
}

pub unsafe fn nfsclnt() {
    core::unimplemented!();
    // syscall0(SYS_NFSCLNT);
}

pub unsafe fn nfssvc() {
    core::unimplemented!();
    // syscall0(SYS_NFSSVC);
}

pub unsafe fn ntp_adjtime() {
    core::unimplemented!();
    // syscall0(SYS_NTP_ADJTIME);
}

pub unsafe fn ntp_gettime() {
    core::unimplemented!();
    // syscall0(SYS_NTP_GETTIME);
}

pub unsafe fn open() {
    core::unimplemented!();
    // syscall0(SYS_OPEN);
}

pub unsafe fn openat() {
    core::unimplemented!();
    // syscall0(SYS_OPENAT);
}

pub unsafe fn openat_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_OPENAT_NOCANCEL);
}

pub unsafe fn openbyid_np() {
    core::unimplemented!();
    // syscall0(SYS_OPENBYID_NP);
}

pub unsafe fn open_dprotected_np() {
    core::unimplemented!();
    // syscall0(SYS_OPEN_DPROTECTED_NP);
}

pub unsafe fn open_extended() {
    core::unimplemented!();
    // syscall0(SYS_OPEN_EXTENDED);
}

pub unsafe fn open_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_OPEN_NOCANCEL);
}

pub unsafe fn os_fault_with_payload() {
    core::unimplemented!();
    // syscall0(SYS_OS_FAULT_WITH_PAYLOAD);
}

pub unsafe fn pathconf() {
    core::unimplemented!();
    // syscall0(SYS_PATHCONF);
}

pub unsafe fn peeloff() {
    core::unimplemented!();
    // syscall0(SYS_PEELOFF);
}

pub unsafe fn persona() {
    core::unimplemented!();
    // syscall0(SYS_PERSONA);
}

pub unsafe fn pid_hibernate() {
    core::unimplemented!();
    // syscall0(SYS_PID_HIBERNATE);
}

pub unsafe fn pid_resume() {
    core::unimplemented!();
    // syscall0(SYS_PID_RESUME);
}

pub unsafe fn pid_shutdown_sockets() {
    core::unimplemented!();
    // syscall0(SYS_PID_SHUTDOWN_SOCKETS);
}

pub unsafe fn pid_suspend() {
    core::unimplemented!();
    // syscall0(SYS_PID_SUSPEND);
}

pub unsafe fn pipe() {
    core::unimplemented!();
    // syscall0(SYS_PIPE);
}

pub unsafe fn pivot_root() {
    core::unimplemented!();
    // syscall0(SYS_PIVOT_ROOT);
}

pub unsafe fn poll() {
    core::unimplemented!();
    // syscall0(SYS_POLL);
}

pub unsafe fn poll_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_POLL_NOCANCEL);
}

pub unsafe fn posix_spawn() {
    core::unimplemented!();
    // syscall0(SYS_POSIX_SPAWN);
}

pub unsafe fn pread() {
    core::unimplemented!();
    // syscall0(SYS_PREAD);
}

pub unsafe fn preadv() {
    core::unimplemented!();
    // syscall0(SYS_PREADV);
}

pub unsafe fn preadv_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_PREADV_NOCANCEL);
}

pub unsafe fn pread_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_PREAD_NOCANCEL);
}

pub unsafe fn process_policy() {
    core::unimplemented!();
    // syscall0(SYS_PROCESS_POLICY);
}

pub unsafe fn proc_info() {
    core::unimplemented!();
    // syscall0(SYS_PROC_INFO);
}

pub unsafe fn proc_info_extended_id() {
    core::unimplemented!();
    // syscall0(SYS_PROC_INFO_EXTENDED_ID);
}

pub unsafe fn proc_rlimit_control() {
    core::unimplemented!();
    // syscall0(SYS_PROC_RLIMIT_CONTROL);
}

pub unsafe fn proc_trace_log() {
    core::unimplemented!();
    // syscall0(SYS_PROC_TRACE_LOG);
}

pub unsafe fn proc_uuid_policy() {
    core::unimplemented!();
    // syscall0(SYS_PROC_UUID_POLICY);
}

pub unsafe fn pselect() {
    core::unimplemented!();
    // syscall0(SYS_PSELECT);
}

pub unsafe fn pselect_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_PSELECT_NOCANCEL);
}

pub unsafe fn psynch_cvbroad() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_CVBROAD);
}

pub unsafe fn psynch_cvclrprepost() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_CVCLRPREPOST);
}

pub unsafe fn psynch_cvsignal() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_CVSIGNAL);
}

pub unsafe fn psynch_cvwait() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_CVWAIT);
}

pub unsafe fn psynch_mutexdrop() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_MUTEXDROP);
}

pub unsafe fn psynch_mutexwait() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_MUTEXWAIT);
}

pub unsafe fn psynch_rw_downgrade() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_DOWNGRADE);
}

pub unsafe fn psynch_rw_longrdlock() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_LONGRDLOCK);
}

pub unsafe fn psynch_rw_rdlock() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_RDLOCK);
}

pub unsafe fn psynch_rw_unlock() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_UNLOCK);
}

pub unsafe fn psynch_rw_unlock2() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_UNLOCK2);
}

pub unsafe fn psynch_rw_upgrade() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_UPGRADE);
}

pub unsafe fn psynch_rw_wrlock() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_WRLOCK);
}

pub unsafe fn psynch_rw_yieldwrlock() {
    core::unimplemented!();
    // syscall0(SYS_PSYNCH_RW_YIELDWRLOCK);
}

pub unsafe fn ptrace() {
    core::unimplemented!();
    // syscall0(SYS_PTRACE);
}

pub unsafe fn pwrite() {
    core::unimplemented!();
    // syscall0(SYS_PWRITE);
}

pub unsafe fn pwritev() {
    core::unimplemented!();
    // syscall0(SYS_PWRITEV);
}

pub unsafe fn pwritev_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_PWRITEV_NOCANCEL);
}

pub unsafe fn pwrite_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_PWRITE_NOCANCEL);
}

pub unsafe fn quotactl() {
    core::unimplemented!();
    // syscall0(SYS_QUOTACTL);
}

pub unsafe fn read() {
    core::unimplemented!();
    // syscall0(SYS_READ);
}

pub unsafe fn readlink() {
    core::unimplemented!();
    // syscall0(SYS_READLINK);
}

pub unsafe fn readlinkat() {
    core::unimplemented!();
    // syscall0(SYS_READLINKAT);
}

pub unsafe fn readv() {
    core::unimplemented!();
    // syscall0(SYS_READV);
}

pub unsafe fn readv_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_READV_NOCANCEL);
}

pub unsafe fn read_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_READ_NOCANCEL);
}

pub unsafe fn reboot() {
    core::unimplemented!();
    // syscall0(SYS_REBOOT);
}

pub unsafe fn recvfrom() {
    core::unimplemented!();
    // syscall0(SYS_RECVFROM);
}

pub unsafe fn recvfrom_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_RECVFROM_NOCANCEL);
}

pub unsafe fn recvmsg() {
    core::unimplemented!();
    // syscall0(SYS_RECVMSG);
}

pub unsafe fn recvmsg_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_RECVMSG_NOCANCEL);
}

pub unsafe fn recvmsg_x() {
    core::unimplemented!();
    // syscall0(SYS_RECVMSG_X);
}

pub unsafe fn removexattr() {
    core::unimplemented!();
    // syscall0(SYS_REMOVEXATTR);
}

pub unsafe fn rename() {
    core::unimplemented!();
    // syscall0(SYS_RENAME);
}

pub unsafe fn renameat() {
    core::unimplemented!();
    // syscall0(SYS_RENAMEAT);
}

pub unsafe fn renameatx_np() {
    core::unimplemented!();
    // syscall0(SYS_RENAMEATX_NP);
}

pub unsafe fn revoke() {
    core::unimplemented!();
    // syscall0(SYS_REVOKE);
}

pub unsafe fn rmdir() {
    core::unimplemented!();
    // syscall0(SYS_RMDIR);
}

pub unsafe fn searchfs() {
    core::unimplemented!();
    // syscall0(SYS_SEARCHFS);
}

pub unsafe fn select() {
    core::unimplemented!();
    // syscall0(SYS_SELECT);
}

pub unsafe fn select_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_SELECT_NOCANCEL);
}

pub unsafe fn semctl() {
    core::unimplemented!();
    // syscall0(SYS_SEMCTL);
}

pub unsafe fn semget() {
    core::unimplemented!();
    // syscall0(SYS_SEMGET);
}

pub unsafe fn semop() {
    core::unimplemented!();
    // syscall0(SYS_SEMOP);
}

pub unsafe fn semsys() {
    core::unimplemented!();
    // syscall0(SYS_SEMSYS);
}

pub unsafe fn sem_close() {
    core::unimplemented!();
    // syscall0(SYS_SEM_CLOSE);
}

pub unsafe fn sem_open() {
    core::unimplemented!();
    // syscall0(SYS_SEM_OPEN);
}

pub unsafe fn sem_post() {
    core::unimplemented!();
    // syscall0(SYS_SEM_POST);
}

pub unsafe fn sem_trywait() {
    core::unimplemented!();
    // syscall0(SYS_SEM_TRYWAIT);
}

pub unsafe fn sem_unlink() {
    core::unimplemented!();
    // syscall0(SYS_SEM_UNLINK);
}

pub unsafe fn sem_wait() {
    core::unimplemented!();
    // syscall0(SYS_SEM_WAIT);
}

pub unsafe fn sem_wait_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_SEM_WAIT_NOCANCEL);
}

pub unsafe fn sendfile() {
    core::unimplemented!();
    // syscall0(SYS_SENDFILE);
}

pub unsafe fn sendmsg() {
    core::unimplemented!();
    // syscall0(SYS_SENDMSG);
}

pub unsafe fn sendmsg_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_SENDMSG_NOCANCEL);
}

pub unsafe fn sendmsg_x() {
    core::unimplemented!();
    // syscall0(SYS_SENDMSG_X);
}

pub unsafe fn sendto() {
    core::unimplemented!();
    // syscall0(SYS_SENDTO);
}

pub unsafe fn sendto_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_SENDTO_NOCANCEL);
}

pub unsafe fn setattrlist() {
    core::unimplemented!();
    // syscall0(SYS_SETATTRLIST);
}

pub unsafe fn setattrlistat() {
    core::unimplemented!();
    // syscall0(SYS_SETATTRLISTAT);
}

pub unsafe fn setaudit_addr() {
    core::unimplemented!();
    // syscall0(SYS_SETAUDIT_ADDR);
}

pub unsafe fn setauid() {
    core::unimplemented!();
    // syscall0(SYS_SETAUID);
}

pub unsafe fn setegid() {
    core::unimplemented!();
    // syscall0(SYS_SETEGID);
}

pub unsafe fn seteuid() {
    core::unimplemented!();
    // syscall0(SYS_SETEUID);
}

pub unsafe fn setgid() {
    core::unimplemented!();
    // syscall0(SYS_SETGID);
}

pub unsafe fn setgroups() {
    core::unimplemented!();
    // syscall0(SYS_SETGROUPS);
}

pub unsafe fn setitimer() {
    core::unimplemented!();
    // syscall0(SYS_SETITIMER);
}

pub unsafe fn setlogin() {
    core::unimplemented!();
    // syscall0(SYS_SETLOGIN);
}

pub unsafe fn setpgid() {
    core::unimplemented!();
    // syscall0(SYS_SETPGID);
}

pub unsafe fn setpriority() {
    core::unimplemented!();
    // syscall0(SYS_SETPRIORITY);
}

pub unsafe fn setprivexec() {
    core::unimplemented!();
    // syscall0(SYS_SETPRIVEXEC);
}

pub unsafe fn setregid() {
    core::unimplemented!();
    // syscall0(SYS_SETREGID);
}

pub unsafe fn setreuid() {
    core::unimplemented!();
    // syscall0(SYS_SETREUID);
}

pub unsafe fn setrlimit() {
    core::unimplemented!();
    // syscall0(SYS_SETRLIMIT);
}

pub unsafe fn setsgroups() {
    core::unimplemented!();
    // syscall0(SYS_SETSGROUPS);
}

pub unsafe fn setsid() {
    core::unimplemented!();
    // syscall0(SYS_SETSID);
}

pub unsafe fn setsockopt() {
    core::unimplemented!();
    // syscall0(SYS_SETSOCKOPT);
}

pub unsafe fn settid() {
    core::unimplemented!();
    // syscall0(SYS_SETTID);
}

pub unsafe fn settid_with_pid() {
    core::unimplemented!();
    // syscall0(SYS_SETTID_WITH_PID);
}

pub unsafe fn settimeofday() {
    core::unimplemented!();
    // syscall0(SYS_SETTIMEOFDAY);
}

pub unsafe fn setuid() {
    core::unimplemented!();
    // syscall0(SYS_SETUID);
}

pub unsafe fn setwgroups() {
    core::unimplemented!();
    // syscall0(SYS_SETWGROUPS);
}

pub unsafe fn setxattr() {
    core::unimplemented!();
    // syscall0(SYS_SETXATTR);
}

pub unsafe fn sfi_ctl() {
    core::unimplemented!();
    // syscall0(SYS_SFI_CTL);
}

pub unsafe fn sfi_pidctl() {
    core::unimplemented!();
    // syscall0(SYS_SFI_PIDCTL);
}

pub unsafe fn shared_region_check_np() {
    core::unimplemented!();
    // syscall0(SYS_SHARED_REGION_CHECK_NP);
}

pub unsafe fn shared_region_map_and_slide_2_np() {
    core::unimplemented!();
    // syscall0(SYS_SHARED_REGION_MAP_AND_SLIDE_2_NP);
}

pub unsafe fn shared_region_map_and_slide_np() {
    core::unimplemented!();
    // syscall0(SYS_SHARED_REGION_MAP_AND_SLIDE_NP);
}

pub unsafe fn shmat() {
    core::unimplemented!();
    // syscall0(SYS_SHMAT);
}

pub unsafe fn shmctl() {
    core::unimplemented!();
    // syscall0(SYS_SHMCTL);
}

pub unsafe fn shmdt() {
    core::unimplemented!();
    // syscall0(SYS_SHMDT);
}

pub unsafe fn shmget() {
    core::unimplemented!();
    // syscall0(SYS_SHMGET);
}

pub unsafe fn shmsys() {
    core::unimplemented!();
    // syscall0(SYS_SHMSYS);
}

pub unsafe fn shm_open() {
    core::unimplemented!();
    // syscall0(SYS_SHM_OPEN);
}

pub unsafe fn shm_unlink() {
    core::unimplemented!();
    // syscall0(SYS_SHM_UNLINK);
}

pub unsafe fn shutdown() {
    core::unimplemented!();
    // syscall0(SYS_SHUTDOWN);
}

pub unsafe fn sigaction() {
    core::unimplemented!();
    // syscall0(SYS_SIGACTION);
}

pub unsafe fn sigaltstack() {
    core::unimplemented!();
    // syscall0(SYS_SIGALTSTACK);
}

pub unsafe fn sigpending() {
    core::unimplemented!();
    // syscall0(SYS_SIGPENDING);
}

pub unsafe fn sigprocmask() {
    core::unimplemented!();
    // syscall0(SYS_SIGPROCMASK);
}

pub unsafe fn sigreturn() {
    core::unimplemented!();
    // syscall0(SYS_SIGRETURN);
}

pub unsafe fn sigsuspend() {
    core::unimplemented!();
    // syscall0(SYS_SIGSUSPEND);
}

pub unsafe fn sigsuspend_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_SIGSUSPEND_NOCANCEL);
}

pub unsafe fn socket() {
    core::unimplemented!();
    // syscall0(SYS_SOCKET);
}

pub unsafe fn socketpair() {
    core::unimplemented!();
    // syscall0(SYS_SOCKETPAIR);
}

pub unsafe fn socket_delegate() {
    core::unimplemented!();
    // syscall0(SYS_SOCKET_DELEGATE);
}

pub unsafe fn stack_snapshot_with_config() {
    core::unimplemented!();
    // syscall0(SYS_STACK_SNAPSHOT_WITH_CONFIG);
}

pub unsafe fn stat() {
    core::unimplemented!();
    // syscall0(SYS_STAT);
}

pub unsafe fn stat64() {
    core::unimplemented!();
    // syscall0(SYS_STAT64);
}

pub unsafe fn stat64_extended() {
    core::unimplemented!();
    // syscall0(SYS_STAT64_EXTENDED);
}

pub unsafe fn statfs() {
    core::unimplemented!();
    // syscall0(SYS_STATFS);
}

pub unsafe fn statfs64() {
    core::unimplemented!();
    // syscall0(SYS_STATFS64);
}

pub unsafe fn stat_extended() {
    core::unimplemented!();
    // syscall0(SYS_STAT_EXTENDED);
}

pub unsafe fn swapon() {
    core::unimplemented!();
    // syscall0(SYS_SWAPON);
}

pub unsafe fn symlink() {
    core::unimplemented!();
    // syscall0(SYS_SYMLINK);
}

pub unsafe fn symlinkat() {
    core::unimplemented!();
    // syscall0(SYS_SYMLINKAT);
}

pub unsafe fn sync() {
    core::unimplemented!();
    // syscall0(SYS_SYNC);
}

pub unsafe fn syscall() {
    core::unimplemented!();
    // syscall0(SYS_SYSCALL);
}

pub unsafe fn sysctl() {
    core::unimplemented!();
    // syscall0(SYS_SYSCTL);
}

pub unsafe fn sysctlbyname() {
    core::unimplemented!();
    // syscall0(SYS_SYSCTLBYNAME);
}

pub unsafe fn system_override() {
    core::unimplemented!();
    // syscall0(SYS_SYSTEM_OVERRIDE);
}

pub unsafe fn task_inspect_for_pid() {
    core::unimplemented!();
    // syscall0(SYS_TASK_INSPECT_FOR_PID);
}

pub unsafe fn task_read_for_pid() {
    core::unimplemented!();
    // syscall0(SYS_TASK_READ_FOR_PID);
}

pub unsafe fn telemetry() {
    core::unimplemented!();
    // syscall0(SYS_TELEMETRY);
}

pub unsafe fn terminate_with_payload() {
    core::unimplemented!();
    // syscall0(SYS_TERMINATE_WITH_PAYLOAD);
}

pub unsafe fn thread_selfcounts() {
    core::unimplemented!();
    // syscall0(SYS_THREAD_SELFCOUNTS);
}

pub unsafe fn thread_selfid() {
    core::unimplemented!();
    // syscall0(SYS_THREAD_SELFID);
}

pub unsafe fn thread_selfusage() {
    core::unimplemented!();
    // syscall0(SYS_THREAD_SELFUSAGE);
}

pub unsafe fn truncate() {
    core::unimplemented!();
    // syscall0(SYS_TRUNCATE);
}

pub unsafe fn ulock_wait() {
    core::unimplemented!();
    // syscall0(SYS_ULOCK_WAIT);
}

pub unsafe fn ulock_wait2() {
    core::unimplemented!();
    // syscall0(SYS_ULOCK_WAIT2);
}

pub unsafe fn ulock_wake() {
    core::unimplemented!();
    // syscall0(SYS_ULOCK_WAKE);
}

pub unsafe fn umask() {
    core::unimplemented!();
    // syscall0(SYS_UMASK);
}

pub unsafe fn umask_extended() {
    core::unimplemented!();
    // syscall0(SYS_UMASK_EXTENDED);
}

pub unsafe fn undelete() {
    core::unimplemented!();
    // syscall0(SYS_UNDELETE);
}

pub unsafe fn unlink() {
    core::unimplemented!();
    // syscall0(SYS_UNLINK);
}

pub unsafe fn unlinkat() {
    core::unimplemented!();
    // syscall0(SYS_UNLINKAT);
}

pub unsafe fn unmount() {
    core::unimplemented!();
    // syscall0(SYS_UNMOUNT);
}

pub unsafe fn usrctl() {
    core::unimplemented!();
    // syscall0(SYS_USRCTL);
}

pub unsafe fn utimes() {
    core::unimplemented!();
    // syscall0(SYS_UTIMES);
}

pub unsafe fn vfork() {
    core::unimplemented!();
    // syscall0(SYS_VFORK);
}

pub unsafe fn vfs_purge() {
    core::unimplemented!();
    // syscall0(SYS_VFS_PURGE);
}

pub unsafe fn vm_pressure_monitor() {
    core::unimplemented!();
    // syscall0(SYS_VM_PRESSURE_MONITOR);
}

pub unsafe fn wait4() {
    core::unimplemented!();
    // syscall0(SYS_WAIT4);
}

pub unsafe fn wait4_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_WAIT4_NOCANCEL);
}

pub unsafe fn waitid() {
    core::unimplemented!();
    // syscall0(SYS_WAITID);
}

pub unsafe fn waitid_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_WAITID_NOCANCEL);
}

pub unsafe fn workq_kernreturn() {
    core::unimplemented!();
    // syscall0(SYS_WORKQ_KERNRETURN);
}

pub unsafe fn workq_open() {
    core::unimplemented!();
    // syscall0(SYS_WORKQ_OPEN);
}

pub unsafe fn work_interval_ctl() {
    core::unimplemented!();
    // syscall0(SYS_WORK_INTERVAL_CTL);
}

pub unsafe fn write() {
    core::unimplemented!();
    // syscall0(SYS_WRITE);
}

pub unsafe fn writev() {
    core::unimplemented!();
    // syscall0(SYS_WRITEV);
}

pub unsafe fn writev_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_WRITEV_NOCANCEL);
}

pub unsafe fn write_nocancel() {
    core::unimplemented!();
    // syscall0(SYS_WRITE_NOCANCEL);
}

pub unsafe fn __channel_get_info() {
    core::unimplemented!();
    // syscall0(SYS___CHANNEL_GET_INFO);
}

pub unsafe fn __channel_get_opt() {
    core::unimplemented!();
    // syscall0(SYS___CHANNEL_GET_OPT);
}

pub unsafe fn __channel_open() {
    core::unimplemented!();
    // syscall0(SYS___CHANNEL_OPEN);
}

pub unsafe fn __channel_set_opt() {
    core::unimplemented!();
    // syscall0(SYS___CHANNEL_SET_OPT);
}

pub unsafe fn __channel_sync() {
    core::unimplemented!();
    // syscall0(SYS___CHANNEL_SYNC);
}

pub unsafe fn __disable_threadsignal() {
    core::unimplemented!();
    // syscall0(SYS___DISABLE_THREADSIGNAL);
}

pub unsafe fn __mach_bridge_remote_time() {
    core::unimplemented!();
    // syscall0(SYS___MACH_BRIDGE_REMOTE_TIME);
}

pub unsafe fn __mac_execve() {
    core::unimplemented!();
    // syscall0(SYS___MAC_EXECVE);
}

pub unsafe fn __mac_getfsstat() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GETFSSTAT);
}

pub unsafe fn __mac_get_fd() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_FD);
}

pub unsafe fn __mac_get_file() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_FILE);
}

pub unsafe fn __mac_get_link() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_LINK);
}

pub unsafe fn __mac_get_mount() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_MOUNT);
}

pub unsafe fn __mac_get_pid() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_PID);
}

pub unsafe fn __mac_get_proc() {
    core::unimplemented!();
    // syscall0(SYS___MAC_GET_PROC);
}

pub unsafe fn __mac_mount() {
    core::unimplemented!();
    // syscall0(SYS___MAC_MOUNT);
}

pub unsafe fn __mac_set_fd() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_FD);
}

pub unsafe fn __mac_set_file() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_FILE);
}

pub unsafe fn __mac_set_link() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_LINK);
}

pub unsafe fn __mac_set_proc() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SET_PROC);
}

pub unsafe fn __mac_syscall() {
    core::unimplemented!();
    // syscall0(SYS___MAC_SYSCALL);
}

pub unsafe fn __nexus_create() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_CREATE);
}

pub unsafe fn __nexus_deregister() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_DEREGISTER);
}

pub unsafe fn __nexus_destroy() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_DESTROY);
}

pub unsafe fn __nexus_get_opt() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_GET_OPT);
}

pub unsafe fn __nexus_open() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_OPEN);
}

pub unsafe fn __nexus_register() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_REGISTER);
}

pub unsafe fn __nexus_set_opt() {
    core::unimplemented!();
    // syscall0(SYS___NEXUS_SET_OPT);
}

pub unsafe fn __old_semwait_signal() {
    core::unimplemented!();
    // syscall0(SYS___OLD_SEMWAIT_SIGNAL);
}

pub unsafe fn __old_semwait_signal_nocancel() {
    core::unimplemented!();
    // syscall0(SYS___OLD_SEMWAIT_SIGNAL_NOCANCEL);
}

pub unsafe fn __pthread_canceled() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_CANCELED);
}

pub unsafe fn __pthread_chdir() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_CHDIR);
}

pub unsafe fn __pthread_fchdir() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_FCHDIR);
}

pub unsafe fn __pthread_kill() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_KILL);
}

pub unsafe fn __pthread_markcancel() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_MARKCANCEL);
}

pub unsafe fn __pthread_sigmask() {
    core::unimplemented!();
    // syscall0(SYS___PTHREAD_SIGMASK);
}

pub unsafe fn __semwait_signal() {
    core::unimplemented!();
    // syscall0(SYS___SEMWAIT_SIGNAL);
}

pub unsafe fn __semwait_signal_nocancel() {
    core::unimplemented!();
    // syscall0(SYS___SEMWAIT_SIGNAL_NOCANCEL);
}

pub unsafe fn __sigwait() {
    core::unimplemented!();
    // syscall0(SYS___SIGWAIT);
}

pub unsafe fn __sigwait_nocancel() {
    core::unimplemented!();
    // syscall0(SYS___SIGWAIT_NOCANCEL);
}

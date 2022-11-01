// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
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

use crate::c_str::CString;
use crate::path::Path;
use crate::syscalls::*;
use crate::sysno::*;
use crate::types::*;

pub unsafe fn accept() {
    core::unimplemented!();
    // syscall0(SYS_ACCEPT);
}

pub unsafe fn access() {
    core::unimplemented!();
    // syscall0(SYS_ACCESS);
}

pub unsafe fn acct() {
    core::unimplemented!();
    // syscall0(SYS_ACCT);
}

pub unsafe fn afssys() {
    core::unimplemented!();
    // syscall0(SYS_AFSSYS);
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

pub unsafe fn aio_write() {
    core::unimplemented!();
    // syscall0(SYS_AIO_WRITE);
}

pub unsafe fn bind() {
    core::unimplemented!();
    // syscall0(SYS_BIND);
}

pub unsafe fn r#break() {
    core::unimplemented!();
    // syscall0(SYS_BREAK);
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

pub unsafe fn chown() {
    core::unimplemented!();
    // syscall0(SYS_CHOWN);
}

pub unsafe fn chroot() {
    core::unimplemented!();
    // syscall0(SYS_CHROOT);
}

pub unsafe fn clock_getcpuclockid2() {
    core::unimplemented!();
    // syscall0(SYS_CLOCK_GETCPUCLOCKID2);
}

pub unsafe fn clock_nanosleep() {
    core::unimplemented!();
    // syscall0(SYS_CLOCK_NANOSLEEP);
}

/// Close a file descriptor.
///
/// ```
/// assert!(nc::close(2).is_ok());
/// ```
pub unsafe fn close(fd: i32) -> Result<(), Errno> {
    let fd = fd as usize;
    syscall1(SYS_CLOSE, fd).map(drop)
}

pub unsafe fn compat_09_ogetdomainname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_09_OGETDOMAINNAME);
}

pub unsafe fn compat_09_osetdomainname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_09_OSETDOMAINNAME);
}

pub unsafe fn compat_09_ouname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_09_OUNAME);
}

pub unsafe fn compat_12_fstat12() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_FSTAT12);
}

pub unsafe fn compat_12_getdirentries() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_GETDIRENTRIES);
}

pub unsafe fn compat_12_lstat12() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_LSTAT12);
}

pub unsafe fn compat_12_msync() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_MSYNC);
}

pub unsafe fn compat_12_oreboot() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_OREBOOT);
}

pub unsafe fn compat_12_oswapon() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_OSWAPON);
}

pub unsafe fn compat_12_stat12() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_12_STAT12);
}

pub unsafe fn compat_13_sigaction13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGACTION13);
}

pub unsafe fn compat_13_sigaltstack13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGALTSTACK13);
}

pub unsafe fn compat_13_sigpending13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGPENDING13);
}

pub unsafe fn compat_13_sigprocmask13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGPROCMASK13);
}

pub unsafe fn compat_13_sigreturn13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGRETURN13);
}

pub unsafe fn compat_13_sigsuspend13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_13_SIGSUSPEND13);
}

pub unsafe fn compat_14_msgctl() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_14_MSGCTL);
}

pub unsafe fn compat_14_shmctl() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_14_SHMCTL);
}

pub unsafe fn compat_14___semctl() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_14___SEMCTL);
}

pub unsafe fn compat_16___sigaction14() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_16___SIGACTION14);
}

pub unsafe fn compat_16___sigreturn14() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_16___SIGRETURN14);
}

pub unsafe fn compat_20_fhstatfs() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_20_FHSTATFS);
}

pub unsafe fn compat_20_fstatfs() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_20_FSTATFS);
}

pub unsafe fn compat_20_getfsstat() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_20_GETFSSTAT);
}

pub unsafe fn compat_20_statfs() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_20_STATFS);
}

pub unsafe fn compat_30_fhopen() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_FHOPEN);
}

pub unsafe fn compat_30_fhstat() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_FHSTAT);
}

pub unsafe fn compat_30_fhstatvfs1() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_FHSTATVFS1);
}

pub unsafe fn compat_30_getdents() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_GETDENTS);
}

pub unsafe fn compat_30_getfh() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_GETFH);
}

pub unsafe fn compat_30_ntp_gettime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_NTP_GETTIME);
}

pub unsafe fn compat_30_socket() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30_SOCKET);
}

pub unsafe fn compat_30___fhstat30() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30___FHSTAT30);
}

pub unsafe fn compat_30___fstat13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30___FSTAT13);
}

pub unsafe fn compat_30___lstat13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30___LSTAT13);
}

pub unsafe fn compat_30___stat13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_30___STAT13);
}

pub unsafe fn compat_40_mount() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_40_MOUNT);
}

pub unsafe fn compat_43_fstat43() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_FSTAT43);
}

pub unsafe fn compat_43_lstat43() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_LSTAT43);
}

pub unsafe fn compat_43_oaccept() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OACCEPT);
}

pub unsafe fn compat_43_ocreat() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OCREAT);
}

pub unsafe fn compat_43_oftruncate() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OFTRUNCATE);
}

pub unsafe fn compat_43_ogetdirentries() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETDIRENTRIES);
}

pub unsafe fn compat_43_ogetdtablesize() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETDTABLESIZE);
}

pub unsafe fn compat_43_ogethostid() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETHOSTID);
}

pub unsafe fn compat_43_ogethostname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETHOSTNAME);
}

pub unsafe fn compat_43_ogetkerninfo() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETKERNINFO);
}

pub unsafe fn compat_43_ogetpagesize() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETPAGESIZE);
}

pub unsafe fn compat_43_ogetpeername() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETPEERNAME);
}

pub unsafe fn compat_43_ogetrlimit() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETRLIMIT);
}

pub unsafe fn compat_43_ogetsockname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OGETSOCKNAME);
}

pub unsafe fn compat_43_okillpg() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OKILLPG);
}

pub unsafe fn compat_43_olseek() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OLSEEK);
}

pub unsafe fn compat_43_ommap() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OMMAP);
}

pub unsafe fn compat_43_oquota() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OQUOTA);
}

pub unsafe fn compat_43_orecv() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_ORECV);
}

pub unsafe fn compat_43_orecvfrom() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_ORECVFROM);
}

pub unsafe fn compat_43_orecvmsg() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_ORECVMSG);
}

pub unsafe fn compat_43_osend() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSEND);
}

pub unsafe fn compat_43_osendmsg() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSENDMSG);
}

pub unsafe fn compat_43_osethostid() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSETHOSTID);
}

pub unsafe fn compat_43_osethostname() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSETHOSTNAME);
}

pub unsafe fn compat_43_osetrlimit() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSETRLIMIT);
}

pub unsafe fn compat_43_osigblock() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSIGBLOCK);
}

pub unsafe fn compat_43_osigsetmask() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSIGSETMASK);
}

pub unsafe fn compat_43_osigstack() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSIGSTACK);
}

pub unsafe fn compat_43_osigvec() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OSIGVEC);
}

pub unsafe fn compat_43_otruncate() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OTRUNCATE);
}

pub unsafe fn compat_43_owait() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_OWAIT);
}

pub unsafe fn compat_43_stat43() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_43_STAT43);
}

pub unsafe fn compat_50_adjtime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_ADJTIME);
}

pub unsafe fn compat_50_aio_suspend() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_AIO_SUSPEND);
}

pub unsafe fn compat_50_clock_getres() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_CLOCK_GETRES);
}

pub unsafe fn compat_50_clock_gettime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_CLOCK_GETTIME);
}

pub unsafe fn compat_50_clock_settime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_CLOCK_SETTIME);
}

pub unsafe fn compat_50_futimes() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_FUTIMES);
}

pub unsafe fn compat_50_getitimer() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_GETITIMER);
}

pub unsafe fn compat_50_getrusage() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_GETRUSAGE);
}

pub unsafe fn compat_50_gettimeofday() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_GETTIMEOFDAY);
}

pub unsafe fn compat_50_kevent() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_KEVENT);
}

pub unsafe fn compat_50_lfs_segwait() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_LFS_SEGWAIT);
}

pub unsafe fn compat_50_lutimes() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_LUTIMES);
}

pub unsafe fn compat_50_mknod() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_MKNOD);
}

pub unsafe fn compat_50_mq_timedreceive() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_MQ_TIMEDRECEIVE);
}

pub unsafe fn compat_50_mq_timedsend() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_MQ_TIMEDSEND);
}

pub unsafe fn compat_50_nanosleep() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_NANOSLEEP);
}

pub unsafe fn compat_50_pollts() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_POLLTS);
}

pub unsafe fn compat_50_pselect() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_PSELECT);
}

pub unsafe fn compat_50_quotactl() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_QUOTACTL);
}

pub unsafe fn compat_50_select() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_SELECT);
}

pub unsafe fn compat_50_setitimer() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_SETITIMER);
}

pub unsafe fn compat_50_settimeofday() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_SETTIMEOFDAY);
}

pub unsafe fn compat_50_timer_gettime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_TIMER_GETTIME);
}

pub unsafe fn compat_50_timer_settime() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_TIMER_SETTIME);
}

pub unsafe fn compat_50_utimes() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_UTIMES);
}

pub unsafe fn compat_50_wait4() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_WAIT4);
}

pub unsafe fn compat_50__lwp_park() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50__LWP_PARK);
}

pub unsafe fn compat_50___fhstat40() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___FHSTAT40);
}

pub unsafe fn compat_50___fstat30() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___FSTAT30);
}

pub unsafe fn compat_50___lstat30() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___LSTAT30);
}

pub unsafe fn compat_50___msgctl13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___MSGCTL13);
}

pub unsafe fn compat_50___ntp_gettime30() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___NTP_GETTIME30);
}

pub unsafe fn compat_50___shmctl13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___SHMCTL13);
}

pub unsafe fn compat_50___sigtimedwait() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___SIGTIMEDWAIT);
}

pub unsafe fn compat_50___stat30() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50___STAT30);
}

pub unsafe fn compat_50_____semctl13() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_50_____SEMCTL13);
}

pub unsafe fn compat_60_sa_enable() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_ENABLE);
}

pub unsafe fn compat_60_sa_preempt() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_PREEMPT);
}

pub unsafe fn compat_60_sa_register() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_REGISTER);
}

pub unsafe fn compat_60_sa_setconcurrency() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_SETCONCURRENCY);
}

pub unsafe fn compat_60_sa_stacks() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_STACKS);
}

pub unsafe fn compat_60_sa_yield() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60_SA_YIELD);
}

pub unsafe fn compat_60__lwp_park() {
    core::unimplemented!();
    // syscall0(SYS_COMPAT_60__LWP_PARK);
}

pub unsafe fn connect() {
    core::unimplemented!();
    // syscall0(SYS_CONNECT);
}

pub unsafe fn dup() {
    core::unimplemented!();
    // syscall0(SYS_DUP);
}

pub unsafe fn dup2() {
    core::unimplemented!();
    // syscall0(SYS_DUP2);
}

pub unsafe fn dup3() {
    core::unimplemented!();
    // syscall0(SYS_DUP3);
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

pub unsafe fn extattrctl() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTRCTL);
}

pub unsafe fn extattr_delete_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_FD);
}

pub unsafe fn extattr_delete_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_FILE);
}

pub unsafe fn extattr_delete_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_DELETE_LINK);
}

pub unsafe fn extattr_get_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_FD);
}

pub unsafe fn extattr_get_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_FILE);
}

pub unsafe fn extattr_get_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_GET_LINK);
}

pub unsafe fn extattr_list_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_FD);
}

pub unsafe fn extattr_list_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_FILE);
}

pub unsafe fn extattr_list_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_LIST_LINK);
}

pub unsafe fn extattr_set_fd() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_FD);
}

pub unsafe fn extattr_set_file() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_FILE);
}

pub unsafe fn extattr_set_link() {
    core::unimplemented!();
    // syscall0(SYS_EXTATTR_SET_LINK);
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

pub unsafe fn fchown() {
    core::unimplemented!();
    // syscall0(SYS_FCHOWN);
}

pub unsafe fn fchownat() {
    core::unimplemented!();
    // syscall0(SYS_FCHOWNAT);
}

pub unsafe fn fchroot() {
    core::unimplemented!();
    // syscall0(SYS_FCHROOT);
}

pub unsafe fn fcntl() {
    core::unimplemented!();
    // syscall0(SYS_FCNTL);
}

pub unsafe fn fdatasync() {
    core::unimplemented!();
    // syscall0(SYS_FDATASYNC);
}

pub unsafe fn fdiscard() {
    core::unimplemented!();
    // syscall0(SYS_FDISCARD);
}

pub unsafe fn fexecve() {
    core::unimplemented!();
    // syscall0(SYS_FEXECVE);
}

pub unsafe fn fgetxattr() {
    core::unimplemented!();
    // syscall0(SYS_FGETXATTR);
}

pub unsafe fn fktrace() {
    core::unimplemented!();
    // syscall0(SYS_FKTRACE);
}

pub unsafe fn flistxattr() {
    core::unimplemented!();
    // syscall0(SYS_FLISTXATTR);
}

pub unsafe fn flock() {
    core::unimplemented!();
    // syscall0(SYS_FLOCK);
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

pub unsafe fn fsetxattr() {
    core::unimplemented!();
    // syscall0(SYS_FSETXATTR);
}

pub unsafe fn fstatat() {
    core::unimplemented!();
    // syscall0(SYS_FSTATAT);
}

pub unsafe fn fstatvfs1() {
    core::unimplemented!();
    // syscall0(SYS_FSTATVFS1);
}

pub unsafe fn fsync() {
    core::unimplemented!();
    // syscall0(SYS_FSYNC);
}

pub unsafe fn fsync_range() {
    core::unimplemented!();
    // syscall0(SYS_FSYNC_RANGE);
}

pub unsafe fn ftruncate() {
    core::unimplemented!();
    // syscall0(SYS_FTRUNCATE);
}

pub unsafe fn futimens() {
    core::unimplemented!();
    // syscall0(SYS_FUTIMENS);
}

pub unsafe fn getcontext() {
    core::unimplemented!();
    // syscall0(SYS_GETCONTEXT);
}

pub unsafe fn getegid() {
    core::unimplemented!();
    // syscall0(SYS_GETEGID);
}

pub unsafe fn geteuid() {
    core::unimplemented!();
    // syscall0(SYS_GETEUID);
}

pub unsafe fn getgid() {
    core::unimplemented!();
    // syscall0(SYS_GETGID);
}

pub unsafe fn getgroups() {
    core::unimplemented!();
    // syscall0(SYS_GETGROUPS);
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

pub unsafe fn getsockopt2() {
    core::unimplemented!();
    // syscall0(SYS_GETSOCKOPT2);
}

pub unsafe fn getuid() {
    core::unimplemented!();
    // syscall0(SYS_GETUID);
}

pub unsafe fn getvfsstat() {
    core::unimplemented!();
    // syscall0(SYS_GETVFSSTAT);
}

pub unsafe fn getxattr() {
    core::unimplemented!();
    // syscall0(SYS_GETXATTR);
}

pub unsafe fn ioctl() {
    core::unimplemented!();
    // syscall0(SYS_IOCTL);
}

pub unsafe fn issetugid() {
    core::unimplemented!();
    // syscall0(SYS_ISSETUGID);
}

pub unsafe fn kill() {
    core::unimplemented!();
    // syscall0(SYS_KILL);
}

pub unsafe fn kqueue() {
    core::unimplemented!();
    // syscall0(SYS_KQUEUE);
}

pub unsafe fn kqueue1() {
    core::unimplemented!();
    // syscall0(SYS_KQUEUE1);
}

pub unsafe fn ktrace() {
    core::unimplemented!();
    // syscall0(SYS_KTRACE);
}

pub unsafe fn lchflags() {
    core::unimplemented!();
    // syscall0(SYS_LCHFLAGS);
}

pub unsafe fn lchmod() {
    core::unimplemented!();
    // syscall0(SYS_LCHMOD);
}

pub unsafe fn lchown() {
    core::unimplemented!();
    // syscall0(SYS_LCHOWN);
}

pub unsafe fn lfs_bmapv() {
    core::unimplemented!();
    // syscall0(SYS_LFS_BMAPV);
}

pub unsafe fn lfs_markv() {
    core::unimplemented!();
    // syscall0(SYS_LFS_MARKV);
}

pub unsafe fn lfs_segclean() {
    core::unimplemented!();
    // syscall0(SYS_LFS_SEGCLEAN);
}

pub unsafe fn lgetxattr() {
    core::unimplemented!();
    // syscall0(SYS_LGETXATTR);
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

pub unsafe fn llistxattr() {
    core::unimplemented!();
    // syscall0(SYS_LLISTXATTR);
}

pub unsafe fn lremovexattr() {
    core::unimplemented!();
    // syscall0(SYS_LREMOVEXATTR);
}

pub unsafe fn lseek() {
    core::unimplemented!();
    // syscall0(SYS_LSEEK);
}

pub unsafe fn lsetxattr() {
    core::unimplemented!();
    // syscall0(SYS_LSETXATTR);
}

pub unsafe fn madvise() {
    core::unimplemented!();
    // syscall0(SYS_MADVISE);
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

pub unsafe fn mkfifo() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFO);
}

pub unsafe fn mkfifoat() {
    core::unimplemented!();
    // syscall0(SYS_MKFIFOAT);
}

pub unsafe fn mknodat() {
    core::unimplemented!();
    // syscall0(SYS_MKNODAT);
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

pub unsafe fn modctl() {
    core::unimplemented!();
    // syscall0(SYS_MODCTL);
}

pub unsafe fn mprotect() {
    core::unimplemented!();
    // syscall0(SYS_MPROTECT);
}

pub unsafe fn mq_close() {
    core::unimplemented!();
    // syscall0(SYS_MQ_CLOSE);
}

pub unsafe fn mq_getattr() {
    core::unimplemented!();
    // syscall0(SYS_MQ_GETATTR);
}

pub unsafe fn mq_notify() {
    core::unimplemented!();
    // syscall0(SYS_MQ_NOTIFY);
}

pub unsafe fn mq_open() {
    core::unimplemented!();
    // syscall0(SYS_MQ_OPEN);
}

pub unsafe fn mq_receive() {
    core::unimplemented!();
    // syscall0(SYS_MQ_RECEIVE);
}

pub unsafe fn mq_send() {
    core::unimplemented!();
    // syscall0(SYS_MQ_SEND);
}

pub unsafe fn mq_setattr() {
    core::unimplemented!();
    // syscall0(SYS_MQ_SETATTR);
}

pub unsafe fn mq_unlink() {
    core::unimplemented!();
    // syscall0(SYS_MQ_UNLINK);
}

pub unsafe fn mremap() {
    core::unimplemented!();
    // syscall0(SYS_MREMAP);
}

pub unsafe fn msgget() {
    core::unimplemented!();
    // syscall0(SYS_MSGGET);
}

pub unsafe fn msgrcv() {
    core::unimplemented!();
    // syscall0(SYS_MSGRCV);
}

pub unsafe fn msgsnd() {
    core::unimplemented!();
    // syscall0(SYS_MSGSND);
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

pub unsafe fn nfssvc() {
    core::unimplemented!();
    // syscall0(SYS_NFSSVC);
}

pub unsafe fn ntp_adjtime() {
    core::unimplemented!();
    // syscall0(SYS_NTP_ADJTIME);
}

/// Open and possibly create a file.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn open<P: AsRef<Path>>(path: P, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    let path = CString::new(path.as_ref());
    let path_ptr = path.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    syscall3(SYS_OPEN, path_ptr, flags, mode).map(|ret| ret as i32)
}

/// Open and possibly create a file within a directory.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn openat<P: AsRef<Path>>(
    dirfd: i32,
    filename: P,
    flags: i32,
    mode: mode_t,
) -> Result<i32, Errno> {
    let dirfd = dirfd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let flags = flags as usize;
    let mode = mode as usize;
    syscall4(SYS_OPENAT, dirfd, filename_ptr, flags, mode).map(|ret| ret as i32)
}

pub unsafe fn paccept() {
    core::unimplemented!();
    // syscall0(SYS_PACCEPT);
}

pub unsafe fn pathconf() {
    core::unimplemented!();
    // syscall0(SYS_PATHCONF);
}

pub unsafe fn pipe() {
    core::unimplemented!();
    // syscall0(SYS_PIPE);
}

pub unsafe fn pipe2() {
    core::unimplemented!();
    // syscall0(SYS_PIPE2);
}

pub unsafe fn poll() {
    core::unimplemented!();
    // syscall0(SYS_POLL);
}

pub unsafe fn posix_fallocate() {
    core::unimplemented!();
    // syscall0(SYS_POSIX_FALLOCATE);
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

pub unsafe fn profil() {
    core::unimplemented!();
    // syscall0(SYS_PROFIL);
}

pub unsafe fn pset_assign() {
    core::unimplemented!();
    // syscall0(SYS_PSET_ASSIGN);
}

pub unsafe fn pset_create() {
    core::unimplemented!();
    // syscall0(SYS_PSET_CREATE);
}

pub unsafe fn pset_destroy() {
    core::unimplemented!();
    // syscall0(SYS_PSET_DESTROY);
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

pub unsafe fn rasctl() {
    core::unimplemented!();
    // syscall0(SYS_RASCTL);
}

/// Read from a file descriptor.
///
/// ```
/// let path = "/etc/passwd";
/// let ret = nc::open(path, nc::O_RDONLY, 0);
/// assert!(ret.is_ok());
/// let fd = ret.unwrap();
/// let mut buf = [0_u8; 4 * 1024];
/// let ret = nc::read(fd, buf.as_mut_ptr() as usize, buf.len());
/// assert!(ret.is_ok());
/// let n_read = ret.unwrap();
/// assert!(n_read <= buf.len() as nc::ssize_t);
/// assert!(nc::close(fd).is_ok());
/// ```
pub unsafe fn read(fd: i32, buf: usize, count: size_t) -> Result<ssize_t, Errno> {
    let fd = fd as usize;
    syscall3(SYS_READ, fd, buf, count).map(|ret| ret as ssize_t)
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

pub unsafe fn reboot() {
    core::unimplemented!();
    // syscall0(SYS_REBOOT);
}

pub unsafe fn recvfrom() {
    core::unimplemented!();
    // syscall0(SYS_RECVFROM);
}

pub unsafe fn recvmmsg() {
    core::unimplemented!();
    // syscall0(SYS_RECVMMSG);
}

pub unsafe fn recvmsg() {
    core::unimplemented!();
    // syscall0(SYS_RECVMSG);
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

pub unsafe fn revoke() {
    core::unimplemented!();
    // syscall0(SYS_REVOKE);
}

pub unsafe fn rmdir() {
    core::unimplemented!();
    // syscall0(SYS_RMDIR);
}

pub unsafe fn sched_yield() {
    core::unimplemented!();
    // syscall0(SYS_SCHED_YIELD);
}

pub unsafe fn semconfig() {
    core::unimplemented!();
    // syscall0(SYS_SEMCONFIG);
}

pub unsafe fn semget() {
    core::unimplemented!();
    // syscall0(SYS_SEMGET);
}

pub unsafe fn semop() {
    core::unimplemented!();
    // syscall0(SYS_SEMOP);
}

pub unsafe fn sendmmsg() {
    core::unimplemented!();
    // syscall0(SYS_SENDMMSG);
}

pub unsafe fn sendmsg() {
    core::unimplemented!();
    // syscall0(SYS_SENDMSG);
}

pub unsafe fn sendto() {
    core::unimplemented!();
    // syscall0(SYS_SENDTO);
}

pub unsafe fn setcontext() {
    core::unimplemented!();
    // syscall0(SYS_SETCONTEXT);
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

pub unsafe fn setpgid() {
    core::unimplemented!();
    // syscall0(SYS_SETPGID);
}

pub unsafe fn setpriority() {
    core::unimplemented!();
    // syscall0(SYS_SETPRIORITY);
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

pub unsafe fn setsid() {
    core::unimplemented!();
    // syscall0(SYS_SETSID);
}

pub unsafe fn setsockopt() {
    core::unimplemented!();
    // syscall0(SYS_SETSOCKOPT);
}

pub unsafe fn setuid() {
    core::unimplemented!();
    // syscall0(SYS_SETUID);
}

pub unsafe fn setxattr() {
    core::unimplemented!();
    // syscall0(SYS_SETXATTR);
}

pub unsafe fn shmat() {
    core::unimplemented!();
    // syscall0(SYS_SHMAT);
}

pub unsafe fn shmdt() {
    core::unimplemented!();
    // syscall0(SYS_SHMDT);
}

pub unsafe fn shmget() {
    core::unimplemented!();
    // syscall0(SYS_SHMGET);
}

pub unsafe fn shutdown() {
    core::unimplemented!();
    // syscall0(SYS_SHUTDOWN);
}

pub unsafe fn sigqueueinfo() {
    core::unimplemented!();
    // syscall0(SYS_SIGQUEUEINFO);
}

pub unsafe fn socketpair() {
    core::unimplemented!();
    // syscall0(SYS_SOCKETPAIR);
}

pub unsafe fn statvfs1() {
    core::unimplemented!();
    // syscall0(SYS_STATVFS1);
}

pub unsafe fn swapctl() {
    core::unimplemented!();
    // syscall0(SYS_SWAPCTL);
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

pub unsafe fn sysarch() {
    core::unimplemented!();
    // syscall0(SYS_SYSARCH);
}

pub unsafe fn syscall() {
    core::unimplemented!();
    // syscall0(SYS_SYSCALL);
}

pub unsafe fn timer_create() {
    core::unimplemented!();
    // syscall0(SYS_TIMER_CREATE);
}

pub unsafe fn timer_delete() {
    core::unimplemented!();
    // syscall0(SYS_TIMER_DELETE);
}

pub unsafe fn timer_getoverrun() {
    core::unimplemented!();
    // syscall0(SYS_TIMER_GETOVERRUN);
}

pub unsafe fn truncate() {
    core::unimplemented!();
    // syscall0(SYS_TRUNCATE);
}

pub unsafe fn umask() {
    core::unimplemented!();
    // syscall0(SYS_UMASK);
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

pub unsafe fn utimensat() {
    core::unimplemented!();
    // syscall0(SYS_UTIMENSAT);
}

pub unsafe fn utrace() {
    core::unimplemented!();
    // syscall0(SYS_UTRACE);
}

pub unsafe fn uuidgen() {
    core::unimplemented!();
    // syscall0(SYS_UUIDGEN);
}

pub unsafe fn vadvise() {
    core::unimplemented!();
    // syscall0(SYS_VADVISE);
}

pub unsafe fn vfork() {
    core::unimplemented!();
    // syscall0(SYS_VFORK);
}

pub unsafe fn wait6() {
    core::unimplemented!();
    // syscall0(SYS_WAIT6);
}

pub unsafe fn write() {
    core::unimplemented!();
    // syscall0(SYS_WRITE);
}

pub unsafe fn writev() {
    core::unimplemented!();
    // syscall0(SYS_WRITEV);
}

pub unsafe fn _ksem_close() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_CLOSE);
}

pub unsafe fn _ksem_destroy() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_DESTROY);
}

pub unsafe fn _ksem_getvalue() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_GETVALUE);
}

pub unsafe fn _ksem_init() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_INIT);
}

pub unsafe fn _ksem_open() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_OPEN);
}

pub unsafe fn _ksem_post() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_POST);
}

pub unsafe fn _ksem_timedwait() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_TIMEDWAIT);
}

pub unsafe fn _ksem_trywait() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_TRYWAIT);
}

pub unsafe fn _ksem_unlink() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_UNLINK);
}

pub unsafe fn _ksem_wait() {
    core::unimplemented!();
    // syscall0(SYS__KSEM_WAIT);
}

pub unsafe fn _lwp_continue() {
    core::unimplemented!();
    // syscall0(SYS__LWP_CONTINUE);
}

pub unsafe fn _lwp_create() {
    core::unimplemented!();
    // syscall0(SYS__LWP_CREATE);
}

pub unsafe fn _lwp_ctl() {
    core::unimplemented!();
    // syscall0(SYS__LWP_CTL);
}

pub unsafe fn _lwp_detach() {
    core::unimplemented!();
    // syscall0(SYS__LWP_DETACH);
}

pub unsafe fn _lwp_exit() {
    core::unimplemented!();
    // syscall0(SYS__LWP_EXIT);
}

pub unsafe fn _lwp_getname() {
    core::unimplemented!();
    // syscall0(SYS__LWP_GETNAME);
}

pub unsafe fn _lwp_getprivate() {
    core::unimplemented!();
    // syscall0(SYS__LWP_GETPRIVATE);
}

pub unsafe fn _lwp_kill() {
    core::unimplemented!();
    // syscall0(SYS__LWP_KILL);
}

pub unsafe fn _lwp_self() {
    core::unimplemented!();
    // syscall0(SYS__LWP_SELF);
}

pub unsafe fn _lwp_setname() {
    core::unimplemented!();
    // syscall0(SYS__LWP_SETNAME);
}

pub unsafe fn _lwp_setprivate() {
    core::unimplemented!();
    // syscall0(SYS__LWP_SETPRIVATE);
}

pub unsafe fn _lwp_suspend() {
    core::unimplemented!();
    // syscall0(SYS__LWP_SUSPEND);
}

pub unsafe fn _lwp_unpark() {
    core::unimplemented!();
    // syscall0(SYS__LWP_UNPARK);
}

pub unsafe fn _lwp_unpark_all() {
    core::unimplemented!();
    // syscall0(SYS__LWP_UNPARK_ALL);
}

pub unsafe fn _lwp_wait() {
    core::unimplemented!();
    // syscall0(SYS__LWP_WAIT);
}

pub unsafe fn _lwp_wakeup() {
    core::unimplemented!();
    // syscall0(SYS__LWP_WAKEUP);
}

pub unsafe fn _pset_bind() {
    core::unimplemented!();
    // syscall0(SYS__PSET_BIND);
}

pub unsafe fn _sched_getaffinity() {
    core::unimplemented!();
    // syscall0(SYS__SCHED_GETAFFINITY);
}

pub unsafe fn _sched_getparam() {
    core::unimplemented!();
    // syscall0(SYS__SCHED_GETPARAM);
}

pub unsafe fn _sched_protect() {
    core::unimplemented!();
    // syscall0(SYS__SCHED_PROTECT);
}

pub unsafe fn _sched_setaffinity() {
    core::unimplemented!();
    // syscall0(SYS__SCHED_SETAFFINITY);
}

pub unsafe fn _sched_setparam() {
    core::unimplemented!();
    // syscall0(SYS__SCHED_SETPARAM);
}

pub unsafe fn __adjtime50() {
    core::unimplemented!();
    // syscall0(SYS___ADJTIME50);
}

pub unsafe fn __aio_suspend50() {
    core::unimplemented!();
    // syscall0(SYS___AIO_SUSPEND50);
}

pub unsafe fn __clock_getres50() {
    core::unimplemented!();
    // syscall0(SYS___CLOCK_GETRES50);
}

pub unsafe fn __clock_gettime50() {
    core::unimplemented!();
    // syscall0(SYS___CLOCK_GETTIME50);
}

pub unsafe fn __clock_settime50() {
    core::unimplemented!();
    // syscall0(SYS___CLOCK_SETTIME50);
}

pub unsafe fn __clone() {
    core::unimplemented!();
    // syscall0(SYS___CLONE);
}

pub unsafe fn __fhopen40() {
    core::unimplemented!();
    // syscall0(SYS___FHOPEN40);
}

pub unsafe fn __fhstat50() {
    core::unimplemented!();
    // syscall0(SYS___FHSTAT50);
}

pub unsafe fn __fhstatvfs140() {
    core::unimplemented!();
    // syscall0(SYS___FHSTATVFS140);
}

pub unsafe fn __fstat50() {
    core::unimplemented!();
    // syscall0(SYS___FSTAT50);
}

pub unsafe fn __futimes50() {
    core::unimplemented!();
    // syscall0(SYS___FUTIMES50);
}

pub unsafe fn __getcwd() {
    core::unimplemented!();
    // syscall0(SYS___GETCWD);
}

pub unsafe fn __getdents30() {
    core::unimplemented!();
    // syscall0(SYS___GETDENTS30);
}

pub unsafe fn __getfh30() {
    core::unimplemented!();
    // syscall0(SYS___GETFH30);
}

pub unsafe fn __getitimer50() {
    core::unimplemented!();
    // syscall0(SYS___GETITIMER50);
}

pub unsafe fn __getlogin() {
    core::unimplemented!();
    // syscall0(SYS___GETLOGIN);
}

pub unsafe fn __getrusage50() {
    core::unimplemented!();
    // syscall0(SYS___GETRUSAGE50);
}

pub unsafe fn __gettimeofday50() {
    core::unimplemented!();
    // syscall0(SYS___GETTIMEOFDAY50);
}

pub unsafe fn __kevent50() {
    core::unimplemented!();
    // syscall0(SYS___KEVENT50);
}

pub unsafe fn __lfs_segwait50() {
    core::unimplemented!();
    // syscall0(SYS___LFS_SEGWAIT50);
}

pub unsafe fn __lstat50() {
    core::unimplemented!();
    // syscall0(SYS___LSTAT50);
}

pub unsafe fn __lutimes50() {
    core::unimplemented!();
    // syscall0(SYS___LUTIMES50);
}

pub unsafe fn __mknod50() {
    core::unimplemented!();
    // syscall0(SYS___MKNOD50);
}

pub unsafe fn __mount50() {
    core::unimplemented!();
    // syscall0(SYS___MOUNT50);
}

pub unsafe fn __mq_timedreceive50() {
    core::unimplemented!();
    // syscall0(SYS___MQ_TIMEDRECEIVE50);
}

pub unsafe fn __mq_timedsend50() {
    core::unimplemented!();
    // syscall0(SYS___MQ_TIMEDSEND50);
}

pub unsafe fn __msgctl50() {
    core::unimplemented!();
    // syscall0(SYS___MSGCTL50);
}

pub unsafe fn __msync13() {
    core::unimplemented!();
    // syscall0(SYS___MSYNC13);
}

pub unsafe fn __nanosleep50() {
    core::unimplemented!();
    // syscall0(SYS___NANOSLEEP50);
}

pub unsafe fn __ntp_gettime50() {
    core::unimplemented!();
    // syscall0(SYS___NTP_GETTIME50);
}

pub unsafe fn __pollts50() {
    core::unimplemented!();
    // syscall0(SYS___POLLTS50);
}

pub unsafe fn __posix_chown() {
    core::unimplemented!();
    // syscall0(SYS___POSIX_CHOWN);
}

pub unsafe fn __posix_fadvise50() {
    core::unimplemented!();
    // syscall0(SYS___POSIX_FADVISE50);
}

pub unsafe fn __posix_fchown() {
    core::unimplemented!();
    // syscall0(SYS___POSIX_FCHOWN);
}

pub unsafe fn __posix_lchown() {
    core::unimplemented!();
    // syscall0(SYS___POSIX_LCHOWN);
}

pub unsafe fn __posix_rename() {
    core::unimplemented!();
    // syscall0(SYS___POSIX_RENAME);
}

pub unsafe fn __pselect50() {
    core::unimplemented!();
    // syscall0(SYS___PSELECT50);
}

pub unsafe fn __quotactl() {
    core::unimplemented!();
    // syscall0(SYS___QUOTACTL);
}

pub unsafe fn __select50() {
    core::unimplemented!();
    // syscall0(SYS___SELECT50);
}

pub unsafe fn __setitimer50() {
    core::unimplemented!();
    // syscall0(SYS___SETITIMER50);
}

pub unsafe fn __setlogin() {
    core::unimplemented!();
    // syscall0(SYS___SETLOGIN);
}

pub unsafe fn __settimeofday50() {
    core::unimplemented!();
    // syscall0(SYS___SETTIMEOFDAY50);
}

pub unsafe fn __shmctl50() {
    core::unimplemented!();
    // syscall0(SYS___SHMCTL50);
}

pub unsafe fn __sigaction_sigtramp() {
    core::unimplemented!();
    // syscall0(SYS___SIGACTION_SIGTRAMP);
}

pub unsafe fn __sigaltstack14() {
    core::unimplemented!();
    // syscall0(SYS___SIGALTSTACK14);
}

pub unsafe fn __sigpending14() {
    core::unimplemented!();
    // syscall0(SYS___SIGPENDING14);
}

pub unsafe fn __sigprocmask14() {
    core::unimplemented!();
    // syscall0(SYS___SIGPROCMASK14);
}

pub unsafe fn __sigsuspend14() {
    core::unimplemented!();
    // syscall0(SYS___SIGSUSPEND14);
}

pub unsafe fn __socket30() {
    core::unimplemented!();
    // syscall0(SYS___SOCKET30);
}

pub unsafe fn __stat50() {
    core::unimplemented!();
    // syscall0(SYS___STAT50);
}

pub unsafe fn __syscall() {
    core::unimplemented!();
    // syscall0(SYS___SYSCALL);
}

pub unsafe fn __sysctl() {
    core::unimplemented!();
    // syscall0(SYS___SYSCTL);
}

pub unsafe fn __timer_gettime50() {
    core::unimplemented!();
    // syscall0(SYS___TIMER_GETTIME50);
}

pub unsafe fn __timer_settime50() {
    core::unimplemented!();
    // syscall0(SYS___TIMER_SETTIME50);
}

pub unsafe fn __utimes50() {
    core::unimplemented!();
    // syscall0(SYS___UTIMES50);
}

pub unsafe fn __vfork14() {
    core::unimplemented!();
    // syscall0(SYS___VFORK14);
}

pub unsafe fn __wait450() {
    core::unimplemented!();
    // syscall0(SYS___WAIT450);
}

pub unsafe fn ___lwp_park60() {
    core::unimplemented!();
    // syscall0(SYS____LWP_PARK60);
}

pub unsafe fn ____semctl50() {
    core::unimplemented!();
    // syscall0(SYS_____SEMCTL50);
}

pub unsafe fn ____sigtimedwait50() {
    core::unimplemented!();
    // syscall0(SYS_____SIGTIMEDWAIT50);
}

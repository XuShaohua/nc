// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use core::arch::asm;

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            in("rsi") a2,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall5(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall6(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("syscall",
            in("rax") n,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            out("rcx") _,  // clobbered by syscalls
            out("r11") _,  // clobbered by syscalls
            lateout("rax") ret,
        );
    }
    check_errno(ret)
}

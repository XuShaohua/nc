// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1),
           "{rsi}"(a2)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1),
           "{rsi}"(a2),
           "{rdx}"(a3)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1),
           "{rsi}"(a2),
           "{rdx}"(a3),
           "{r10}"(a4)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
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
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1),
           "{rsi}"(a2),
           "{rdx}"(a3),
           "{r10}"(a4),
           "{r8}"(a5)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
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
        llvm_asm!("syscall"
         : "={rax}"(ret)
         : "{rax}"(n),
           "{rdi}"(a1),
           "{rsi}"(a2),
           "{rdx}"(a3),
           "{r10}"(a4),
           "{r8}"(a5),
           "{r9}"(a6)
         : "rcx",
           "r11",
           "memory"
         : "volatile");
    }
    check_errno(ret)
}

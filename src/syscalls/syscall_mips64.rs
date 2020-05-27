// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    let mut n = n;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "={r7}"(ret)
         :
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    let mut n = n;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "={r7}"(ret)
         : "{r4}"(a1)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    let mut n = n;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "={r7}"(ret)
         : "{r4}"(a1),
           "{r5}"(a2)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    let mut n = n;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "={r7}"(ret)
         : "{r4}"(a1),
           "{r5}"(a2),
           "{r6}"(a3)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let mut n = n;
    let mut a4 = a4;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "+{r7}"(a4)
         : "{r4}"(a1),
           "{r5}"(a2),
           "{r6}"(a3)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
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
    let mut n = n;
    let mut a4 = a4;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "+{r7}"(a4)
         : "{r4}"(a1),
           "{r5}"(a2),
           "{r6}"(a3),
           "{r8}"(a5)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
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
    let mut n = n;
    let mut a4 = a4;
    unsafe {
        llvm_asm!("syscall"
         : "+&{r2}"(n), "+{r7}"(a4)
         : "{r4}"(a1),
           "{r5}"(a2),
           "{r6}"(a3),
           "{r8}"(a5),
           "{r9}"(a6)
         : "$1", "$3", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
         : "volatile");
    }
    check_errno(n)
}

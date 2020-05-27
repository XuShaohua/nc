// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let mut r0 = n;
    let r3: usize;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "={r3}"(r3)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let mut r0 = n;
    let mut r3 = a1;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let mut r0 = n;
    let mut r3 = a1;
    let mut r4 = a2;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3), "+{r4}"(r4)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let mut r0 = n;
    let mut r3 = a1;
    let mut r4 = a2;
    let mut r5 = a3;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3), "+{r4}"(r4), "+{r5}"(r5)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let mut r0 = n;
    let mut r3 = a1;
    let mut r4 = a2;
    let mut r5 = a3;
    let mut r6 = a4;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3), "+{r4}"(r4), "+{r5}"(r5), "+{r6}"(r6)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
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
    let mut r0 = n;
    let mut r3 = a1;
    let mut r4 = a2;
    let mut r5 = a3;
    let mut r6 = a4;
    let mut r7 = a5;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3), "+{r4}"(r4), "+{r5}"(r5), "+{r6}"(r6), "+{r7}"(r7)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
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
    let mut r0 = n;
    let mut r3 = a1;
    let mut r4 = a2;
    let mut r5 = a3;
    let mut r6 = a4;
    let mut r7 = a5;
    let mut r8 = a6;
    unsafe {
        llvm_asm!("sc"
         : "+{r0}"(r0), "+{r3}"(r3), "+{r4}"(r4), "+{r5}"(r5), "+{r6}"(r6), "+{r7}"(r7), "+{r8}"(r8)
         :
         : "memory", "cr0", "r4", "5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
         : "volatile");
    }
    check_errno(r3)
}

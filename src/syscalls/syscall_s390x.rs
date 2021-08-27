// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("svc 0"
         : "={r}"(ret)
         : "{r1}"(n)
         : "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("svc 0"
         : "={r}"(ret)
         : "{r1}"(n),
           "{r2}"(a1)
         : "memory"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        llvm_asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3),
           "{x3}"(a4)
         : "memory" "cc"
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
        llvm_asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3),
           "{x3}"(a4),
           "{x4}"(a5)
         : "memory" "cc"
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
        llvm_asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3),
           "{x3}"(a4),
           "{x4}"(a5),
           "{x5}"(a6)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

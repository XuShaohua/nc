// Copyright (c) 2023 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::module_name_repetitions)]

use core::arch::asm;

use super::types::{check_errno, Errno, Sysno};

#[inline]
pub unsafe fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), 
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0)
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let mut a1: usize = a2;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0), "r{a1}"(a1)
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let mut a1: usize = a2;
    let mut a2: usize = a3;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0), "r{a1}"(a1), "r{a2}"(a2)
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall4(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let mut a1: usize = a2;
    let mut a2: usize = a3;
    let mut a3: usize = a4;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0), "r{a1}"(a1), "r{a2}"(a2), "r{a3}"(a3)
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall5(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let mut a1: usize = a2;
    let mut a2: usize = a3;
    let mut a3: usize = a4;
    let mut a4: usize = a5;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0), "r{a1}"(a1), "r{a2}"(a2), "r{a3}"(a3), "r{a4}"(a4)
        : "memory"
        : "volatile");
    check_errno(ret)
}

#[inline]
pub unsafe fn syscall6(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Result<usize, Errno> {
    let mut a7: usize = n;
    let mut a0: usize = a1;
    let mut a1: usize = a2;
    let mut a2: usize = a3;
    let mut a3: usize = a4;
    let mut a4: usize = a5;
    let mut a5: usize = a6;
    let ret: usize;
    llvm_asm!("ecall",
        : "=r{a0}")(ret)
        : "r{a7}"(a7), "r{a0}"(a0), "r{a1}"(a1), "r{a2}"(a2), "r{a3}"(a3), "r{a4}"(a4), "r{a5}"(a5)
        : "memory"
        : "volatile");
    check_errno(ret)
}

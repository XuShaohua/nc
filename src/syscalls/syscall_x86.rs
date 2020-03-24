// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

use super::types::*;

#[inline(always)]
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1),
           "{ecx}"(a2)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1),
           "{ecx}"(a2),
           "{edx}"(a3)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    let ret: usize;
    unsafe {
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1),
           "{ecx}"(a2),
           "{edx}"(a3),
           "{esi}"(a4)
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
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1),
           "{ecx}"(a2),
           "{edx}"(a3),
           "{esi}"(a4),
           "{edi}"(a5)
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
        asm!("int $$0x80"
         : "={eax}"(ret)
         : "{eax}"(n),
           "{ebx}"(a1),
           "{ecx}"(a2),
           "{edx}"(a3),
           "{esi}"(a4),
           "{edi}"(a5)
           "{ebp}"(a6)
         : "memory" "cc"
         : "volatile");
    }
    check_errno(ret)
}

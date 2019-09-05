pub mod call;
pub mod errno;
pub mod sysno;

pub use call::*;
pub use errno::*;
pub use sysno::*;

const MAX_ERRNO: i32 = 4095;

#[inline(always)]
pub fn check_errno(ret: usize) -> Result<usize, Errno> {
    let reti = ret as isize;
    if reti < 0 && reti >= (-MAX_ERRNO) as isize {
        let reti = (-reti) as Errno;
        Err(reti)
    } else {
        Ok(ret)
    }
}

#[inline(always)]
pub unsafe fn syscall0(n: Sysno) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={r}"(ret)
         : "{r1}"(n)
         : "memory"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={r}"(ret)
         : "{r1}"(n),
           "{r2}"(a1)
         : "memory"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
         : "memory" "cc"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3)
         : "memory" "cc"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall4(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3),
           "{x3}"(a4)
         : "memory" "cc"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall5(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
         : "={x0}"(ret)
         : "{x8}"(n),
           "{x0}"(a1),
           "{x1}"(a2),
           "{x2}"(a3),
           "{x3}"(a4),
           "{x4}"(a5)
         : "memory" "cc"
         : "volatile");
    check_errno(ret)
}

#[inline(always)]
pub unsafe fn syscall6(
    n: Sysno,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Result<usize, Errno> {
    let ret: usize;
    asm!("svc 0"
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
    check_errno(ret)
}

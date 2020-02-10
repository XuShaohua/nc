#[link(name = "syscall", kind = "static")]
extern "C" {
    pub fn __syscall0(n: usize) -> usize;

    pub fn __syscall1(n: usize, a1: usize) -> usize;

    pub fn __syscall2(n: usize, a1: usize, a2: usize) -> usize;

    pub fn __syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize;

    pub fn __syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize;

    pub fn __syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize;

    pub fn __syscall6(
        n: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
    ) -> usize;
}

/// Error No.
pub type Errno = i32;

/// Syscall No.
pub type Sysno = usize;

const MAX_ERRNO: Errno = 4095;

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
pub fn syscall0(n: Sysno) -> Result<usize, Errno> {
    unsafe { check_errno(__syscall0(n)) }
}

#[inline(always)]
pub fn syscall1(n: Sysno, a1: usize) -> Result<usize, Errno> {
    unsafe { check_errno(__syscall1(n, a1)) }
}

#[inline(always)]
pub fn syscall2(n: Sysno, a1: usize, a2: usize) -> Result<usize, Errno> {
    unsafe { check_errno(__syscall2(n, a1, a2)) }
}

#[inline(always)]
pub fn syscall3(n: Sysno, a1: usize, a2: usize, a3: usize) -> Result<usize, Errno> {
    unsafe { check_errno(__syscall3(n, a1, a2, a3)) }
}

#[inline(always)]
pub fn syscall4(n: Sysno, a1: usize, a2: usize, a3: usize, a4: usize) -> Result<usize, Errno> {
    unsafe { check_errno(__syscall4(n, a1, a2, a3, a4)) }
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
    unsafe { check_errno(__syscall5(n, a1, a2, a3, a4, a5)) }
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
    unsafe { check_errno(__syscall6(n, a1, a2, a3, a4, a5, a6)) }
}

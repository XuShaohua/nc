
pub mod c;
pub mod consts;
pub mod errno;
pub mod sysno;
pub mod types;

use sysno::SysNo;

// Copy from kmcallister/syscall.rs
#[inline(always)]
pub unsafe fn syscall0(n: SysNo) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall1(n: SysNo, a1: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall2(n: SysNo, a1: usize, a2: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall3(n: SysNo, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2), "{rdx}"(a3)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall4(n: SysNo, a1: usize, a2: usize, a3: usize,
                       a4: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2), "{rdx}"(a3),
                     "{r10}"(a4)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}


#[inline(always)]
pub unsafe fn syscall5(n: SysNo, a1: usize, a2: usize, a3: usize,
                       a4: usize, a5: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2), "{rdx}"(a3),
                     "{r10}"(a4), "{r8}"(a5)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall6(n: SysNo, a1: usize, a2: usize, a3: usize,
                       a4: usize, a5: usize, a6: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2), "{rdx}"(a3),
                     "{r10}"(a4), "{r8}"(a5), "{r9}"(a6)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}


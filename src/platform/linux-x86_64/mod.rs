
pub mod c;
pub mod nums;
pub mod types;

// Copy from kmcallister/syscall.rs
#[inline(always)]
pub unsafe fn syscall0(n: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    asm!("syscall" : "={rax}"(ret)
                   : "{rax}"(n), "{rdi}"(a1), "{rsi}"(a2), "{rdx}"(a3)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}


/// Change data segment size.
pub unsafe fn sbrk(incr: intptr_t) -> Result<usize, Errno> {
    let incr = incr as usize;
    unsafe { syscall1(SYS_SBRK, incr) }
}

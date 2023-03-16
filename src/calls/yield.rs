/// Yield the processor.
pub unsafe fn yield() -> Result<(), Errno> {
    syscall0(SYS_YIELD).map(drop)
}

pub unsafe fn r#break(addr: usize) -> Result<(), Errno> {
    unsafe { syscall1(SYS_BREAK, addr).map(drop) }
}

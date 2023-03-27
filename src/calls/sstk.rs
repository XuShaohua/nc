pub unsafe fn sstk(incr: i32) -> Result<(), Errno> {
    // TODO(Shaohua): Check return type
    let incr = incr as usize;
    syscall1(SYS_SSTK, incr).map(drop)
}

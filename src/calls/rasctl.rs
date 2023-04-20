/// Restartable atomic sequences
pub unsafe fn rasctl(addr: uintptr, len: size_t, op: i32) -> Result<(), Errno> {
    let op = op as usize;
    syscall3(SYS_RASCTL, addr, len, op).map(drop)
}

/// Controls signals blocking with a simple memory write
pub unsafe fn sigfastblock(cmd: i32, ptr: usize) -> Result<(), Errno> {
    let cmd = cmd as usize;
    syscall2(SYS_SIGFASTBLOCK, cmd, ptr).map(drop)
}

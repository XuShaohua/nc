/// Controls signals blocking with a simple memory write
pub unsafe fn sigfastblock(cmd: i32, ptr: *mut u32) -> Result<(), Errno> {
    let cmd = cmd as usize;
    let ptr = ptr as usize;
    unsafe { syscall2(SYS_SIGFASTBLOCK, cmd, ptr).map(drop) }
}

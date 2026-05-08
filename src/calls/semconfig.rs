pub unsafe fn semconfig(flag: i32) -> Result<i32, Errno> {
    let flag = flag as usize;
    unsafe { syscall1(SYS_SEMCONFIG, flag).map(|val| val as i32) }
}

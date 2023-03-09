/// Execute a new program.
pub unsafe fn fexecve(fd: i32, argv: &[&str], env: &[&str]) -> Result<(), Errno> {
    let fd = fd as usize;
    let argv_ptr = argv.as_ptr() as usize;
    let env_ptr = env.as_ptr() as usize;
    syscall3(SYS_FEXECVE, fd, argv_ptr, env_ptr).map(drop)
}

/// Operate on Secure Computing state of the process.
pub unsafe fn seccomp(operation: u32, flags: u32, args: usize) -> Result<(), Errno> {
    let operation = operation as usize;
    let flags = flags as usize;
    syscall3(SYS_SECCOMP, operation, flags, args).map(drop)
}

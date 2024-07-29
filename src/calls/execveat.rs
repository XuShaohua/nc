/// Execute a new program relative to a directory file descriptor.
///
/// # Examples
///
/// ```
/// let args = [""];
/// let env = [""];
/// let ret = unsafe { nc::execveat(nc::AT_FDCWD, "/bin/ls", &args, &env, 0) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn execveat<P: AsRef<Path>>(
    fd: i32,
    filename: P,
    argv: &[&str],
    env: &[&str],
    flags: i32,
) -> Result<(), Errno> {
    // TODO(Shaohua): type of argv and env will be changed.
    // And return value might be changed too.

    // FIXME(Shaohua): Convert into CString first.
    let fd = fd as usize;
    let filename = CString::new(filename.as_ref());
    let filename_ptr = filename.as_ptr() as usize;
    let argv_ptr = argv.as_ptr() as usize;
    let env_ptr = env.as_ptr() as usize;
    let flags = flags as usize;
    syscall5(SYS_EXECVEAT, fd, filename_ptr, argv_ptr, env_ptr, flags).map(drop)
}

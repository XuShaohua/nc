/// Wait for process to change state.
pub unsafe fn __wait450(
    pid: pid_t,
    wstatus: &mut i32,
    options: i32,
    rusage: &mut rusage_t,
) -> Result<pid_t, Errno> {
    let pid = pid as usize;
    let wstatus_ptr = core::ptr::from_mut(wstatus) as usize;
    let options = options as usize;
    let rusage_ptr = core::ptr::from_mut(rusage) as usize;
    unsafe {
        syscall4(SYS___WAIT450, pid, wstatus_ptr, options, rusage_ptr).map(|ret| ret as pid_t)
    }
}

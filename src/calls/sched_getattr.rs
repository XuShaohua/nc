/// Get scheduling policy and attributes
pub unsafe fn sched_getattr(
    pid: pid_t,
    attr: &mut sched_attr_t,
    size: u32,
    flags: u32,
) -> Result<(), Errno> {
    let pid = pid as usize;
    let attr_ptr = attr as *mut sched_attr_t as usize;
    let size = size as usize;
    let flags = flags as usize;
    syscall4(SYS_SCHED_GETATTR, pid, attr_ptr, size, flags).map(drop)
}

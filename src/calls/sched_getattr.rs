/// Get scheduling policy and attributes
pub unsafe fn sched_getattr(pid: pid_t, attr: &mut sched_attr_t, flags: u32) -> Result<(), Errno> {
    let pid = pid as usize;
    let attr_ptr = core::ptr::from_mut(attr) as usize;
    let size = core::mem::size_of::<sched_attr_t>();
    let flags = flags as usize;
    unsafe { syscall4(SYS_SCHED_GETATTR, pid, attr_ptr, size, flags).map(drop) }
}

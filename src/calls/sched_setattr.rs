/// Set the RT priority of a thread.
pub unsafe fn sched_setattr(pid: pid_t, attr: &sched_attr_t, flags: u32) -> Result<(), Errno> {
    let pid = pid as usize;
    let attr_ptr = core::ptr::from_ref(attr) as usize;
    let flags = flags as usize;
    unsafe { syscall3(SYS_SCHED_SETATTR, pid, attr_ptr, flags).map(drop) }
}

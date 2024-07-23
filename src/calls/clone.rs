/// Create a child process.
pub unsafe fn clone(
    clone_flags: usize,
    newsp: usize,
    parent_tid: &mut i32,
    child_tid: &mut i32,
    tls: usize,
) -> Result<pid_t, Errno> {
    let parent_tid_ptr = parent_tid as *mut i32 as usize;
    let child_tid_ptr = child_tid as *mut i32 as usize;
    syscall5(
        SYS_CLONE,
        clone_flags,
        newsp,
        parent_tid_ptr,
        child_tid_ptr,
        tls,
    )
    .map(|ret| ret as pid_t)
}

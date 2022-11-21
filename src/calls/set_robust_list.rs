/// Set the robust-futex list head of a task.
pub unsafe fn set_robust_list(heads: &mut [robust_list_head_t]) -> Result<(), Errno> {
    let heads_ptr = heads.as_mut_ptr() as usize;
    let len = heads.len();
    syscall2(SYS_SET_ROBUST_LIST, heads_ptr, len).map(drop)
}

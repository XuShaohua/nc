/// Get list of robust futexes.
// TODO(Shaohua): Fix argument type.
pub unsafe fn get_robust_list(
    pid: pid_t,
    head_ptr: &mut usize,
    len_ptr: &mut size_t,
) -> Result<(), Errno> {
    let pid = pid as usize;
    let head_ptr = head_ptr as *mut usize as usize;
    let len_ptr = len_ptr as *mut size_t as usize;
    syscall3(SYS_GET_ROBUST_LIST, pid, head_ptr, len_ptr).map(drop)
}

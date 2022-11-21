/// Set default NUMA memory policy for a thread and its children
pub unsafe fn set_mempolicy(mode: i32, nmask: *const usize, maxnode: usize) -> Result<(), Errno> {
    let mode = mode as usize;
    let nmask = nmask as usize;
    syscall3(SYS_SET_MEMPOLICY, mode, nmask, maxnode).map(drop)
}

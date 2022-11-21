/// Retrieve NUMA memory policy for a thread
pub unsafe fn get_mempolicy(
    mode: &mut i32,
    nmask: &mut usize,
    maxnode: usize,
    addr: usize,
    flags: usize,
) -> Result<(), Errno> {
    let mode_ptr = mode as *mut i32 as usize;
    let nmask_ptr = nmask as *mut usize as usize;
    syscall5(SYS_GET_MEMPOLICY, mode_ptr, nmask_ptr, maxnode, addr, flags).map(drop)
}

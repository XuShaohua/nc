/// Execute an SPU context.
pub unsafe fn spu_run(fd: i32, npc: &mut u32, status: &mut u32) -> Result<usize, Errno> {
    let fd = fd as usize;
    let npc_ptr = core::ptr::from_mut(npc) as usize;
    let status_ptr = core::ptr::from_mut(status) as usize;
    unsafe { syscall3(SYS_SPU_RUN, fd, npc_ptr, status_ptr) }
}

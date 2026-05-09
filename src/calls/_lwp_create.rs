/// Crate a new thread.
pub unsafe fn _lwp_craete(
    ctx: &mut ucontext_t,
    flags: usize,
    id: &mut lwpid_t,
) -> Result<(), Errno> {
    let ctx_ptr = core::ptr::from_mut(ctx) as usize;
    let id_ptr = core::ptr::from_mut(id) as usize;
    unsafe { syscall3(SYS__LWP_CREATE, ctx_ptr, flags, id_ptr).map(drop) }
}

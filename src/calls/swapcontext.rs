/// Exchange user thread context.
pub unsafe fn swapcontext(old_ctx: &mut ucontext_t, ctx: &ucontext_t) -> Result<(), Errno> {
    let old_ctx_ptr = core::ptr::from_mut(old_ctx) as usize;
    let ctx_ptr = core::ptr::from_ref(ctx) as usize;
    unsafe { syscall2(SYS_SWAPCONTEXT, old_ctx_ptr, ctx_ptr).map(drop) }
}

/// Set user thread context.
pub unsafe fn setcontext(ctx: &ucontext_t) -> Result<(), Errno> {
    let ctx_ptr = core::ptr::from_ref(ctx) as usize;
    unsafe { syscall1(SYS_SETCONTEXT, ctx_ptr).map(drop) }
}
